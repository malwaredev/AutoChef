/**
 * Decryption candidates for the ciphers malware and ransomware use, when the key material is
 * present in the sample (a loader script, a config blob, a .NET settings class …).
 *
 * Every guess is first checked in JavaScript (Node crypto / @noble/ciphers, whose output matches
 * CyberChef's) and only proposed when it produces clean output. The proposal is then executed by
 * CyberChef like every other step. Without the key nothing is proposed: files encrypted by
 * ransomware with per-file keys wrapped by RSA/ECC cannot be decrypted this way, and AutoChef
 * says so instead of guessing.
 */
import crypto from "node:crypto";
import { pbkdf2 } from "./pbkdf2.mjs";
import { chacha20, chacha20orig, chacha8, chacha12 } from "@noble/ciphers/chacha.js";
import { salsa20, xsalsa20 } from "@noble/ciphers/salsa.js";
import { printableRatio, detectFileType, languageScore, latin1, binaryStrings, extractIOCs, iocCount } from "./analyze.mjs";

const op = (name, args) => ({ op: name, args });
const hex = b => Buffer.from(b).toString("hex");
const H = b => ({ option: "Hex", string: hex(b) });

/** Known PBKDF2 salts of .NET RAT families (published analyses; see README "Sources"). */
export const KNOWN_SALTS = [
    { family: "AsyncRAT / QuasarRAT", salt: Buffer.from("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941", "hex"), iterations: 50000 },
    { family: "DcRAT", salt: Buffer.from("DcRatByqwqdanchun", "ascii"), iterations: 50000 },
];

/** Key material written in a script: hex / Base64 strings, byte arrays, plain strings. */
export function harvestSecrets(text) {
    const t = text.slice(0, 500000);
    const out = [];
    const push = (bytes, how) => {
        if (!bytes || bytes.length < 4 || bytes.length > 64) return;
        if (out.some(o => Buffer.compare(o.bytes, bytes) === 0)) return;
        out.push({ bytes: Buffer.from(bytes), how });
    };
    for (const m of t.matchAll(/["'`]([0-9a-fA-F]{16}|[0-9a-fA-F]{24}|[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})["'`]/g)) push(Buffer.from(m[1], "hex"), "hex string");
    for (const m of t.matchAll(/["'`]([A-Za-z0-9+/]{11,44}={0,2})["'`]/g)) {
        const b = Buffer.from(m[1], "base64");
        if ([8, 12, 16, 24, 32].includes(b.length)) push(b, "Base64 string");
    }
    for (const m of t.matchAll(/(?:0x[0-9a-fA-F]{1,2}\s*,\s*){7,63}0x[0-9a-fA-F]{1,2}/g)) push(Buffer.from(m[0].split(/\s*,\s*/).map(x => parseInt(x, 16))), "byte array");
    for (const m of t.matchAll(/[({\[]\s*((?:\d{1,3}\s*,\s*){7,63}\d{1,3})\s*[)}\]]/g)) {
        const v = m[1].split(/\s*,\s*/).map(Number);
        if (v.every(x => x < 256)) push(Buffer.from(v), "decimal byte array");
    }
    for (const m of t.matchAll(/["'`]([ -~]{4,64})["'`]/g)) {
        const s = m[1];
        if (/\s{2}|^https?:|[\\{}<>]/.test(s) || (s.length > 40 && !/^[A-Za-z0-9+/=_-]+$/.test(s))) continue;
        push(Buffer.from(s, "utf8"), "string");
        if (out.length > 80) break;
    }
    return out.slice(0, 80);
}

export function rc4(key, data) {
    const S = new Uint8Array(256); for (let i = 0; i < 256; i++) S[i] = i;
    for (let i = 0, j = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 255; [S[i], S[j]] = [S[j], S[i]]; }
    const out = new Uint8Array(data.length);
    for (let n = 0, i = 0, j = 0; n < data.length; n++) { i = (i + 1) & 255; j = (j + S[i]) & 255; [S[i], S[j]] = [S[j], S[i]]; out[n] = data[n] ^ S[(S[i] + S[j]) & 255]; }
    return out;
}

/** Wrong key → random bytes; right key → text, JSON, a real file. Returns a quality > 0 or 0. */
export function cryptoOk(pt) {
    const b = new Uint8Array(pt);
    if (b.length < 16) return 0;
    if (detectFileType(b)?.final) return 2;
    const p = printableRatio(b, Math.min(b.length, 8192));
    // short outputs are printable by chance far too often: demand words as well
    if (p >= 0.95 && (b.length >= 96 || languageScore(latin1(b, 4000)) > 0.3)) return 1 + p;
    // UTF-16 text
    let z = 0; const n = Math.min(b.length, 2000);
    for (let i = 1; i < n; i += 2) if (b[i] === 0) z++;
    if (z > n * 0.45) return 1.5;
    if (p >= 0.85 && languageScore(latin1(b, 4000)) > 0.35) return 1.2;
    // structured configs with control-character delimiters (e.g. Remcos 7c 1f 1e 1e 7c): mostly printable runs with real indicators
    if (p >= 0.6) {
        const st = binaryStrings(b, 4);
        if (st.coverage >= 0.55 && (iocCount(extractIOCs(st.text)) > 0 || languageScore(st.text) > 0.3)) return 1.1;
    }
    return 0;
}

const safe = f => { try { return f(); } catch { return null; } };

/**
 * Ciphertext is `cipher` (binary); key material comes from `scriptText` (the loader / settings).
 * Returns candidate objects {ops, why, prior, strong, q}.
 */
export function scriptKeyCandidates(cipher, scriptText, userSecrets = []) {
    const found = [];
    const user = userSecrets.length > 0;
    scriptText = scriptText || "";
    if (cipher.length < 8 || (!scriptText && !user)) return found;
    const scriptHasCrypto = /aes|rijndael|rc4|arcfour|chacha|salsa|des\b|3des|crypt|cipher|decrypt|iv\b|nonce|key|xor|rc2|blowfish|rabbit|tea\b|xtea|sm4|twofish|rc6/i.test(scriptText);
    if (!scriptHasCrypto && !user) return found;
    // keys the user typed come first; their "why" says so
    const secrets = [...userSecrets, ...(scriptHasCrypto ? harvestSecrets(scriptText) : [])].slice(0, 90);
    if (!secrets.length) return found;
    const src = k => k.user ? k.how : `the key found in the script (${k.how})`;
    const sample = cipher.subarray(0, 8192);
    const of = n => secrets.filter(s => s.bytes.length === n);
    const push = (q, ops, why) => { if (q) found.push({ q, ops, why, prior: 19, strong: true }); };

    // ---- AES: CBC / ECB / CTR / CFB / OFB; IV from script, first 16 bytes, or zero
    for (const k of secrets.filter(s => [16, 24, 32].includes(s.bytes.length))) {
        const bits = k.bytes.length * 8;
        const ivs = [...of(16).map(s => ({ iv: s.bytes, why: `IV from the script (${s.how})` })), { iv: Buffer.alloc(16), why: "all-zero IV" }];
        for (const mode of ["CBC", "CTR", "CFB", "OFB", "ECB"]) {
            const algo = `aes-${bits}-${mode.toLowerCase()}`;
            const tries = mode === "ECB" ? [{ iv: null, why: "", data: cipher }] : [...ivs.map(x => ({ ...x, data: cipher })), { iv: cipher.subarray(0, 16), why: "IV = first 16 bytes of the data", data: cipher.subarray(16), fromInput: true }];
            for (const t of tries) {
                // block modes: PKCS#7 padding first, then "no padding" (.NET Padding = Zeros / None, as in real loaders)
                for (const noPad of (mode === "CBC" || mode === "ECB") ? [false, true] : [false]) {
                    if (noPad && t.data.length % 16) continue;
                    const pt = safe(() => {
                        const d = crypto.createDecipheriv(algo, k.bytes, t.iv);
                        if (mode !== "CBC" && mode !== "ECB") return d.update(t.data.subarray(0, 8192));
                        if (noPad) { d.setAutoPadding(false); return d.update(t.data.subarray(0, 8192)); }
                        if (t.data.length > 65536) {
                            // large data: check the PKCS#7 padding on the last block only (CBC: IV = previous block)
                            const L = t.data.length - (t.data.length % 16);
                            const tail = crypto.createDecipheriv(algo, k.bytes, mode === "ECB" ? null : t.data.subarray(L - 32, L - 16));
                            Buffer.concat([tail.update(t.data.subarray(L - 16, L)), tail.final()]); // throws on bad padding
                            return d.update(t.data.subarray(0, 8192));
                        }
                        return Buffer.concat([d.update(t.data), d.final()]);
                    });
                    if (!pt) continue;
                    const m = noPad ? `${mode}/NoPadding` : mode;
                    const ops = t.fromInput
                        ? [op("AES Decrypt", [H(k.bytes), H(Buffer.alloc(0)), 16, m, "Raw", "Raw", H(Buffer.alloc(0)), H(Buffer.alloc(0)), "From start"])]
                        : [op("AES Decrypt", [H(k.bytes), H(t.iv || Buffer.alloc(0)), 16, m, "Raw", "Raw", H(Buffer.alloc(0)), H(Buffer.alloc(0)), "Off"])];
                    const q = cryptoOk(pt);
                    push(q ? q - (noPad ? 0.01 : 0) : 0, ops, `AES-${bits}-${m} with ${src(k)}${t.why ? ", " + t.why : ""}${noPad ? " (no PKCS#7 padding, e.g. .NET Padding = Zeros)" : ""}`);
                    if (q) break;
                }
            }
        }
    }

    // ---- ChaCha20 / ChaCha12 / ChaCha8 / Salsa20 / XSalsa20 (32- or 16-byte key; nonce from script, prepended or zero)
    for (const k of secrets.filter(s => s.bytes.length === 32 || s.bytes.length === 16)) {
        const nonceSets = {
            8: [...of(8).map(s => ({ n: s.bytes, why: `nonce from the script (${s.how})` })), { n: Buffer.alloc(8), why: "zero nonce" }, { n: cipher.subarray(0, 8), why: "nonce = first 8 bytes", skip: 8 }],
            12: [...of(12).map(s => ({ n: s.bytes, why: `nonce from the script (${s.how})` })), { n: Buffer.alloc(12), why: "zero nonce" }, { n: cipher.subarray(0, 12), why: "nonce = first 12 bytes", skip: 12 }],
            24: [...of(24).map(s => ({ n: s.bytes, why: `nonce from the script (${s.how})` })), { n: cipher.subarray(0, 24), why: "nonce = first 24 bytes", skip: 24 }],
        };
        const ciphers = [
            { name: "ChaCha20", op: "ChaCha", rounds: "20", len: 12, f: (k, n, d, c) => chacha20(k, n, d, undefined, c) },
            { name: "ChaCha20 (original, 64-bit nonce)", op: "ChaCha", rounds: "20", len: 8, f: (k, n, d, c) => chacha20orig(k, n, d, undefined, c) },
            { name: "ChaCha12", op: "ChaCha", rounds: "12", len: 12, f: (k, n, d, c) => chacha12(k, n, d, undefined, c) },
            { name: "ChaCha8", op: "ChaCha", rounds: "8", len: 12, f: (k, n, d, c) => chacha8(k, n, d, undefined, c) },
            { name: "Salsa20", op: "Salsa20", rounds: "20", len: 8, f: (k, n, d, c) => salsa20(k, n, d, undefined, c) },
            { name: "XSalsa20", op: "XSalsa20", rounds: "20", len: 24, f: (k, n, d, c) => xsalsa20(k, n, d, undefined, c), key32: true },
        ];
        for (const c of ciphers) {
            if (c.key32 && k.bytes.length !== 32) continue;
            for (const nn of nonceSets[c.len]) {
                const data = nn.skip ? cipher.subarray(nn.skip) : cipher;
                for (const counter of [0, 1]) {
                    const pt = safe(() => c.f(new Uint8Array(k.bytes), new Uint8Array(nn.n), new Uint8Array(data.subarray(0, 4096)), counter));
                    if (!pt) continue;
                    const q = cryptoOk(pt);
                    if (!q) continue;
                    const ops = [];
                    if (nn.skip) ops.push(op("Drop bytes", [0, nn.skip, false]));
                    ops.push(op(c.op, [H(k.bytes), H(nn.n), counter, c.rounds, "Raw", "Raw"]));
                    push(q, ops, `${c.name} with ${src(k)}, ${nn.why}${counter ? ", counter 1" : ""}`);
                }
            }
        }
    }

    // ---- RC4 (and RC4-drop) with any string / bytes from the script
    for (const k of secrets) {
        push(cryptoOk(rc4(k.bytes, sample)), [op("RC4", [H(k.bytes), "Latin1", "Latin1"])], `RC4 with ${k.user ? k.how : `the key found in the script (${k.how}: "${Buffer.from(k.bytes).toString("latin1").slice(0, 24)}")`}`);
    }

    // ---- DES / 3DES / Blowfish / RC2 via Node (when the OpenSSL build still provides them)
    for (const k of secrets.filter(s => [8, 16, 24].includes(s.bytes.length))) {
        const algos = k.bytes.length === 8 ? [["des", "DES Decrypt"], ["bf", "Blowfish Decrypt"]] : k.bytes.length === 24 ? [["des-ede3", "Triple DES Decrypt"], ["bf", "Blowfish Decrypt"]] : [["bf", "Blowfish Decrypt"], ["rc2", "RC2 Decrypt"]];
        for (const [algo, ccOp] of algos) {
            for (const mode of ["cbc", "ecb"]) {
                const ivs = mode === "ecb" ? [null] : [...of(8).map(s => s.bytes), Buffer.alloc(8)];
                for (const iv of ivs) {
                    const pt = safe(() => { const d = crypto.createDecipheriv(`${algo}-${mode}`, k.bytes, iv); return Buffer.concat([d.update(cipher.subarray(0, 65536 - (65536 % 8))), cipher.length <= 65536 ? d.final() : Buffer.alloc(0)]); });
                    if (!pt) continue;
                    const args = ccOp === "RC2 Decrypt" ? [H(k.bytes), H(iv || Buffer.alloc(0)), "Raw", "Raw"] : [H(k.bytes), H(iv || Buffer.alloc(0)), mode.toUpperCase(), "Raw", "Raw"];
                    push(cryptoOk(pt), [op(ccOp, args)], `${ccOp.replace(" Decrypt", "")}-${mode.toUpperCase()} with ${src(k)}`);
                }
            }
        }
    }

    // ---- multi-byte XOR with a key written in the script
    if (/xor/i.test(scriptText) || user) {
        for (const k of secrets) {
            if (k.bytes.length < 2) continue;
            const pt = Buffer.from(sample.map((x, i) => x ^ k.bytes[i % k.bytes.length]));
            push(cryptoOk(pt), [op("XOR", [{ option: "Hex", string: hex(k.bytes).match(/../g).join(" ") }, "Standard", false])], `XOR with ${k.user ? k.how : `the key found in the script (${k.how}: "${Buffer.from(k.bytes).toString("latin1").slice(0, 24)}")`}`);
        }
    }

    // ciphers Node can't verify here: propose (unverified, lower prior) only when the script names them
    const named = (scriptText.match(/\b(rabbit|xxtea|xtea|tea|sm4|twofish|rc6)\b/gi) || []).map(x => x.toLowerCase());
    if (named.length) {
        const k16 = secrets.filter(s => s.bytes.length === 16).slice(0, 3);
        const iv = [...of(16), ...of(8)].slice(0, 2);
        // IV stored in front of the ciphertext
        const pre = cipher.length > 32 ? [{ bytes: Buffer.from(cipher.subarray(0, 16)), prepended: true }] : [];
        for (const k of k16) {
            if (named.includes("xxtea")) found.push({ q: 0.5, prior: 9, ops: [op("XXTEA Decrypt", [H(k.bytes)])], why: `The script names XXTEA; key from the script (${k.how}) [checked by CyberChef only]` });
            if (named.includes("xtea")) found.push({ q: 0.5, prior: 9, ops: [op("XTEA Decrypt", [H(k.bytes), H((of(8)[0] || {}).bytes || Buffer.alloc(8)), "CBC", "Raw", "Raw", "PKCS5"])], why: `The script names XTEA; key from the script (${k.how}) [checked by CyberChef only]` });
            if (named.includes("tea")) found.push({ q: 0.5, prior: 9, ops: [op("TEA Decrypt", [H(k.bytes), H((of(8)[0] || {}).bytes || Buffer.alloc(8)), "CBC", "Raw", "Raw", "PKCS5"])], why: `The script names TEA; key from the script (${k.how}) [checked by CyberChef only]` });
            if (named.includes("sm4")) for (const v of [...iv.filter(x => x.bytes.length === 16), ...pre]) found.push({ q: v.prepended ? 0.49 : 0.5, prior: 9, ops: [...(v.prepended ? [op("Drop bytes", [0, 16, false])] : []), op("SM4 Decrypt", [H(k.bytes), H(v.bytes), "CBC", "Raw", "Raw"])], why: `The script names SM4; key and IV from the script [checked by CyberChef only]` });
            if (named.includes("twofish")) for (const v of [...iv.filter(x => x.bytes.length === 16), ...pre]) found.push({ q: v.prepended ? 0.49 : 0.5, prior: 9, ops: [...(v.prepended ? [op("Drop bytes", [0, 16, false])] : []), op("Twofish Decrypt", [H(k.bytes), H(v.bytes), "CBC", "Raw", "Raw", "PKCS5"])], why: `The script names Twofish; key and IV from the script [checked by CyberChef only]` });
            if (named.includes("rc6")) for (const v of [...iv.filter(x => x.bytes.length === 16), ...pre]) found.push({ q: v.prepended ? 0.49 : 0.5, prior: 9, ops: [...(v.prepended ? [op("Drop bytes", [0, 16, false])] : []), op("RC6 Decrypt", [H(k.bytes), H(v.bytes), "CBC", "Raw", "Raw", "PKCS5", 32, 20])], why: `The script names RC6; key and IV from the script [checked by CyberChef only]` });
            if (named.includes("rabbit")) for (const v of of(8)) found.push({ q: 0.5, prior: 9, ops: [op("Rabbit", [H(k.bytes), H(v.bytes), "Big", "Raw", "Raw"])], why: `The script names Rabbit; key and IV from the script [checked by CyberChef only]` });
        }
    }

    // one proposal per algorithm + key: the variant (IV/nonce/mode) that decrypts most cleanly
    const best = new Map();
    const unverified = [];
    for (const f of found) {
        if (f.q < 1) { unverified.push(f); continue; } // CyberChef-only checks: keep every key/IV pairing
        const a = f.ops[f.ops.length - 1];
        const k = a.op + "|" + JSON.stringify(a.args[0]);
        if (!best.has(k) || f.q > best.get(k).q) best.set(k, f);
    }
    const verified = [...best.values()].sort((a, b) => b.q - a.q).slice(0, 5);
    return verified.length ? verified : unverified.slice(0, 8);
}

/**
 * Config blobs that carry their own key (no script needed):
 *  - REvil/Sodinokibi: [32-byte RC4 key][CRC32][length][RC4 data]
 *  - Remcos SETTINGS:   [key length (1 byte)][key][RC4 data]
 *  - generic: RC4 key of 8/16/32/64 bytes prepended to the data
 */
export function embeddedKeyCandidates(data) {
    const found = [];
    if (data.length < 24) return found;
    const tryRc4 = (keyStart, keyLen, dataStart, why, extra = []) => {
        if (dataStart >= data.length) return;
        const key = data.subarray(keyStart, keyStart + keyLen);
        if (key.length !== keyLen || key.every(b => b === 0)) return;
        const pt = rc4(key, data.subarray(dataStart, dataStart + 4096));
        const q = cryptoOk(pt);
        if (q) found.push({ q, prior: 20, strong: true, why, ops: [op("Drop bytes", [0, dataStart, false]), ...extra, op("RC4", [H(key), "Latin1", "Latin1"])] });
    };
    // REvil: length field at 36..40 (little endian)
    const len = data.length >= 40 ? (data[36] | (data[37] << 8) | (data[38] << 16) | (data[39] << 24)) >>> 0 : 0;
    if (len > 0 && len <= data.length - 40) tryRc4(0, 32, 40, "Config blob with its own key: 32-byte RC4 key, CRC32 and length, then RC4 data (layout of the REvil/Sodinokibi configuration)", [op("Take bytes", [0, len, false])]);
    // Remcos: first byte = key length
    const kl = data[0];
    if (kl >= 4 && kl <= 128 && kl + 1 < data.length) tryRc4(1, kl, 1 + kl, `Config blob with its own key: first byte is the RC4 key length (${kl}), then the key, then the data (layout of the Remcos SETTINGS resource)`);
    // generic prepended keys
    for (const k of [8, 16, 32, 64]) for (const skip of [0, 4, 8]) tryRc4(0, k, k + skip, `RC4 key stored in the first ${k} bytes of the data${skip ? ` (followed by a ${skip}-byte header)` : ""}`);
    const seen = new Set();
    return found.sort((a, b) => b.q - a.q).filter(f => { const k = JSON.stringify(f.ops); if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 3);
}

/**
 * .NET RAT settings (AsyncRAT, QuasarRAT, DcRAT and forks): every setting is
 * Base64([HMAC-SHA256 32][IV 16][AES-256-CBC data]); key = PBKDF2-SHA1(master key, salt, 50000).
 * `text` is the settings class / strings of the sample.
 */
export async function pbkdf2ConfigCandidates(text) {
    const found = [];
    const blobs = [...new Set(text.match(/[A-Za-z0-9+/]{64,}={0,2}/g) || [])].map(b => Buffer.from(b, "base64")).filter(b => b.length >= 64 && (b.length - 48) % 16 === 0).slice(0, 20);
    if (!blobs.length) return found;
    const passes = new Set();
    for (const m of text.matchAll(/["'`]?([A-Za-z0-9+/]{16,88}={0,2})["'`]?/g)) {
        passes.add(m[1]);
        const d = Buffer.from(m[1], "base64").toString("latin1");
        if (/^[ -~]{8,64}$/.test(d)) passes.add(d);
    }
    for (const m of text.matchAll(/["'`]([ -~]{8,64})["'`]/g)) passes.add(m[1]);
    for (const pass of [...passes].slice(0, 40)) {
        for (const s of KNOWN_SALTS) {
            const key = await pbkdf2(Buffer.from(pass, "utf8"), s.salt, s.iterations, 32, "sha1");
            // every setting must decrypt with valid PKCS#7 padding (a wrong key fails ~255/256 times per field)
            const pts = blobs.map(b => safe(() => { const d = crypto.createDecipheriv("aes-256-cbc", key, b.subarray(32, 48)); return Buffer.concat([d.update(b.subarray(48)), d.final()]); }));
            const okCount = pts.filter(Boolean).length;
            const joined = Buffer.concat(pts.filter(Boolean));
            if (!pts[0] || okCount < Math.max(1, Math.ceil(blobs.length * 0.6)) || printableRatio(joined, joined.length) < 0.9) continue;
            found.push({
                q: 2, prior: 22, strong: true,
                why: `${s.family} settings: key = PBKDF2-SHA1(master key "${pass.slice(0, 24)}…", ${s.family} salt, ${s.iterations} iterations) → AES-256-CBC; each value is [HMAC 32][IV 16][data]. (CyberChef can rebuild the key with "Derive PBKDF2 key")`,
                ops: [
                    op("Subsection", ["[A-Za-z0-9+/]{64,}={0,2}", true, true, true]),
                    op("From Base64", ["A-Za-z0-9+/=", true, false]),
                    op("Drop bytes", [0, 32, false]),
                    op("AES Decrypt", [H(key), H(Buffer.alloc(0)), 16, "CBC", "Raw", "Raw", H(Buffer.alloc(0)), H(Buffer.alloc(0)), "From start"]),
                    op("Merge", [true]),
                ],
            });
            return found;
        }
    }
    return found;
}

/** Does this look like data encrypted with a key we don't have? */
export function encryptedAssessment(bytes) {
    const n = Math.min(bytes.length, 1 << 20);
    if (n < 64) return null;
    const f = new Uint32Array(256);
    for (let i = 0; i < n; i++) f[bytes[i]]++;
    let e = 0;
    for (const c of f) if (c) { const p = c / n; e -= p * Math.log2(p); }
    // expected entropy of n uniformly random bytes (Miller–Madow bias correction): small samples look less than 8 bits
    const expected = 8 - 255 / (2 * n * Math.LN2);
    // chi-square against uniform: compressed data is high-entropy too but less uniform
    const exp = n / 256;
    let chi = 0;
    for (const c of f) chi += (c - exp) ** 2 / exp;
    const ft = detectFileType(bytes);
    if (ft) return null;
    if (e >= expected - 0.25 && chi < 400 + n / 50) return { entropy: +e.toFixed(3), chiSquare: Math.round(chi), verdict: "encrypted" };
    // ECB mode leaks repetition: identical 16-byte blocks repeat, the bytes inside the blocks are still random
    if (n >= 64 && n % 16 === 0) {
        const blocks = new Map();
        for (let i = 0; i + 16 <= n; i += 16) { const k = Buffer.from(bytes.subarray(i, i + 16)).toString("hex"); blocks.set(k, (blocks.get(k) || 0) + 1); }
        const distinct = [...blocks.keys()];
        if (distinct.length < n / 16 * 0.9) {
            const uniq = Buffer.from(distinct.join(""), "hex");
            const g = new Uint32Array(256); for (const b of uniq) g[b]++;
            let e2 = 0; for (const c of g) if (c) { const p = c / uniq.length; e2 -= p * Math.log2(p); }
            const exp2 = 8 - 255 / (2 * uniq.length * Math.LN2);
            if (e2 >= exp2 - 0.3) return { entropy: +e.toFixed(3), chiSquare: Math.round(chi), verdict: "encrypted", mode: "ECB (repeated 16-byte blocks)" };
        }
    }
    return null;
}
