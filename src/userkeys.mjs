/**
 * Keys, passwords and IVs typed by the user (UI key field, CLI --key, API "keys").
 *
 * Each line of the key field is one secret. A line is tried as text (UTF-8), and also as hex
 * or Base64 when it parses that way, so "0011…ff", "c2VjcmV0…" and "P@ssw0rd" all work.
 * A second line of the right length is used as the IV / nonce.
 *
 * Every proposal is first decrypted here in JavaScript (Node crypto / @noble, whose output matches
 * CyberChef's) and only offered when the result is clean; CyberChef then runs it like any other step.
 */
import crypto from "node:crypto";
import { pbkdf2 } from "./pbkdf2.mjs";
import { cryptoOk } from "./crypto.mjs";
import { languageScore, printableRatio } from "./analyze.mjs";

const op = (name, args) => ({ op: name, args });
const hex = b => Buffer.from(b).toString("hex");
const H = b => ({ option: "Hex", string: hex(b) });
const EMPTY = Buffer.alloc(0);
const safe = f => { try { return f(); } catch { return null; } };

/** One entry per interpretation of each line: {bytes, how, text} */
export function parseUserKeys(keys = []) {
    const out = [];
    const push = (bytes, how, text) => {
        if (!bytes || !bytes.length || bytes.length > 128) return;
        if (out.some(o => o.bytes.equals(bytes))) return;
        out.push({ bytes: Buffer.from(bytes), how, text, user: true });
    };
    for (const raw of keys.flatMap(k => String(k).split(/\r?\n/))) {
        const line = raw.trim();
        if (!line) continue;
        push(Buffer.from(line, "utf8"), `your key "${line.length > 40 ? line.slice(0, 37) + "…" : line}" as text`, line);
        const h = line.replace(/^0x/i, "").replace(/[\s:,-]|\\x|0x/gi, "");
        if (h.length >= 8 && h.length % 2 === 0 && /^[0-9a-f]+$/i.test(h)) push(Buffer.from(h, "hex"), "your key as hex", line);
        if (/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(line) && !/^[0-9a-f]+$/i.test(line)) {
            const b = Buffer.from(line.replace(/-/g, "+").replace(/_/g, "/"), "base64");
            if ([8, 12, 16, 24, 32, 48, 64].includes(b.length)) push(b, "your key as Base64", line);
        }
    }
    return out;
}

function evpBytesToKey(pass, salt, len, hash, iter = 1) {
    let d = EMPTY, prev = EMPTY;
    while (d.length < len) {
        prev = crypto.createHash(hash).update(Buffer.concat([prev, pass, salt])).digest();
        for (let i = 1; i < iter; i++) prev = crypto.createHash(hash).update(prev).digest();
        d = Buffer.concat([d, prev]);
    }
    return d.subarray(0, len);
}

/** OpenSSL `enc` / CryptoJS "Salted__" format: [Salted__][8-byte salt][AES-CBC data] */
async function opensslSalted(bytes, passwords) {
    const found = [];
    if (bytes.length < 32 || bytes.subarray(0, 8).toString("latin1") !== "Salted__") return found;
    const salt = bytes.subarray(8, 16), data = bytes.subarray(16);
    const kdfs = [
        { name: "PBKDF2-SHA256, 10,000 iterations (openssl enc -pbkdf2)", f: (p, n) => pbkdf2(p, salt, 10000, n, "sha256") },
        { name: "EVP_BytesToKey MD5 (CryptoJS default, openssl enc -md md5)", f: (p, n) => evpBytesToKey(p, salt, n, "md5") },
        { name: "EVP_BytesToKey SHA-256 (openssl enc, OpenSSL ≥ 1.1 without -pbkdf2)", f: (p, n) => evpBytesToKey(p, salt, n, "sha256") },
        { name: "PBKDF2-SHA256, 100,000 iterations", f: (p, n) => pbkdf2(p, salt, 100000, n, "sha256") },
        { name: "PBKDF2-SHA1, 10,000 iterations", f: (p, n) => pbkdf2(p, salt, 10000, n, "sha1") },
        { name: "PBKDF2-SHA512, 10,000 iterations", f: (p, n) => pbkdf2(p, salt, 10000, n, "sha512") },
    ];
    for (const pw of passwords.filter(p => p.how.includes("as text"))) {
        for (const kdf of kdfs) {
            for (const bits of [256, 128, 192]) {
                const km = await kdf.f(pw.bytes, bits / 8 + 16);
                const key = km.subarray(0, bits / 8), iv = km.subarray(bits / 8, bits / 8 + 16);
                const pt = safe(() => { const d = crypto.createDecipheriv(`aes-${bits}-cbc`, key, iv); return Buffer.concat([d.update(data), d.final()]); });
                const q = pt && cryptoOk(pt);
                if (!q) continue;
                found.push({
                    q: q + 1, prior: 32, strong: true,
                    ops: [op("Drop bytes", [0, 16, false]), op("AES Decrypt", [H(key), H(iv), 16, "CBC", "Raw", "Raw", H(EMPTY), H(EMPTY), "Off"])],
                    why: `OpenSSL/CryptoJS "Salted__" data: AES-${bits}-CBC, key and IV derived from ${pw.how} with ${kdf.name} and salt ${hex(salt)}. ` +
                        `(In CyberChef: Derive ${kdf.name.startsWith("PBKDF2") ? "PBKDF2" : "EVP"} key gives the same ${bits}-bit key + IV.)`,
                });
                return found;
            }
        }
    }
    return found;
}

/** Fernet token (gAAAAA…): HMAC-SHA256 checked, AES-128-CBC */
function fernet(text, secrets) {
    const t = text.trim();
    if (!/^gAAAAA[A-Za-z0-9_-]{40,}={0,2}$/.test(t)) return [];
    const tok = Buffer.from(t, "base64url");
    if (tok.length < 57 || tok[0] !== 0x80) return [];
    for (const s of secrets) {
        const key = s.bytes.length === 32 ? s.bytes : null;
        if (!key) continue;
        const body = tok.subarray(0, tok.length - 32), mac = tok.subarray(tok.length - 32);
        if (!crypto.createHmac("sha256", key.subarray(0, 16)).update(body).digest().equals(mac)) continue;
        const pt = safe(() => { const d = crypto.createDecipheriv("aes-128-cbc", key.subarray(16), body.subarray(9, 25)); return Buffer.concat([d.update(body.subarray(25)), d.final()]); });
        if (!pt) continue;
        return [{ q: 3, prior: 34, strong: true, ops: [op("Fernet Decrypt", [Buffer.from(key).toString("base64url")])], why: `Fernet token (version 0x80, HMAC-SHA256 verified) decrypted with ${s.how}` }];
    }
    return [];
}

const vig = (s, key) => {
    const k = key.toLowerCase().replace(/[^a-z]/g, "");
    let j = 0;
    return s.replace(/[a-z]/gi, c => {
        const o = c <= "Z" ? 65 : 97;
        const r = String.fromCharCode((c.charCodeAt(0) - o - (k.charCodeAt(j++ % k.length) - 97) + 26) % 26 + o);
        return r;
    });
};

/**
 * Candidates that use the user's keys. `scriptKeyCandidates` (crypto.mjs) does the AES / ChaCha /
 * RC4 / DES / Blowfish / XOR trials with these secrets; this adds the formats that need a password
 * derivation or a token check, and keyed classical ciphers on text.
 */
export function userTextCandidates(text, secrets) {
    const found = [...fernet(text, secrets)];
    // Vigenère with a word key
    const letters = (text.match(/[A-Za-z]/g) || []).length;
    if (letters >= 4 && letters / text.length > 0.5 && printableRatio(Buffer.from(text, "latin1")) > 0.95) {
        const before = languageScore(text);
        for (const s of secrets.filter(x => x.how.includes("as text") && /^[A-Za-z]{2,32}$/.test(x.text))) {
            const pt = vig(text, s.text);
            const after = languageScore(pt);
            // the user named the key: a short all-letter message (ATTACKATDAWN) is enough
            if ((after > before + 0.2 && after > 0.4) || letters < 40) found.push({ q: 1 + after, prior: 30, strong: true, ops: [op("Vigenère Decode", [s.text])], why: `Vigenère with ${s.how} (language score ${before.toFixed(2)} → ${after.toFixed(2)})` });
        }
    }
    return found;
}

export async function userBinaryCandidates(bytes, secrets) {
    return opensslSalted(Buffer.from(bytes), secrets);
}
