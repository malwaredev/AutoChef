/**
 * Encoders for the advanced test suite. Implemented with Node's standard library (and the
 * lz-string package for LZString), never with CyberChef, so tests can't pass by symmetry.
 * Each transform: { id, kind, make(buf, rng) -> Buffer, lossy? } – "lossy" ones only keep
 * letters (A1Z26, Bacon, Morse…) and are checked case-insensitively on letters/digits only.
 */
import zlib from "node:zlib";
import crypto from "node:crypto";
import LZString from "lz-string";

const T = s => Buffer.from(s, "latin1");
const S = b => Buffer.from(b).toString("latin1");

function baseN(buf, alphabet) {
    let n = BigInt("0x" + (Buffer.from(buf).toString("hex") || "0"));
    const B = BigInt(alphabet.length);
    let out = "";
    while (n > 0n) { out = alphabet[Number(n % B)] + out; n /= B; }
    for (const b of buf) { if (b === 0) out = alphabet[0] + out; else break; }
    return out;
}
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
function base62(buf) { // CyberChef "From Base62" treats input as a big number without leading-zero handling
    let n = BigInt("0x" + (Buffer.from(buf).toString("hex") || "0"));
    let out = ""; while (n > 0n) { out = B62[Number(n % 62n)] + out; n /= 62n; } return out || "0";
}
const B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
function base45(buf) {
    let out = "";
    for (let i = 0; i < buf.length; i += 2) {
        if (i + 1 < buf.length) { let n = buf[i] * 256 + buf[i + 1]; const c = n % 45; n = (n - c) / 45; const d = n % 45; const e = (n - d) / 45; out += B45[c] + B45[d] + B45[e]; }
        else { const n = buf[i]; out += B45[n % 45] + B45[Math.floor(n / 45)]; }
    }
    return out;
}
function ascii85(buf) {
    let out = "";
    for (let i = 0; i < buf.length; i += 4) {
        const chunk = Buffer.alloc(4); Buffer.from(buf).copy(chunk, 0, i, i + 4);
        const len = Math.min(4, buf.length - i);
        let n = chunk.readUInt32BE(0);
        if (n === 0 && len === 4) { out += "z"; continue; }
        const c = []; for (let k = 0; k < 5; k++) { c.unshift(String.fromCharCode(33 + (n % 85))); n = Math.floor(n / 85); }
        out += c.join("").slice(0, len + 1);
    }
    return out;
}
function base32(buf) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "", out = "";
    for (const b of buf) bits += b.toString(2).padStart(8, "0");
    for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
    while (out.length % 8) out += "=";
    return out;
}
const rotN = (s, k, digits = false) => s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - o + k) % 26 + o); }).replace(digits ? /[0-9]/g : /$^/, d => String((+d + k) % 10));
const rot47 = s => s.replace(/[!-~]/g, c => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)));
const atbash = s => s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode(25 - (c.charCodeAt(0) - o) + o); });
const MORSE = { A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..", 0: "-----", 1: ".----", 2: "..---", 3: "...--", 4: "....-", 5: ".....", 6: "-....", 7: "--...", 8: "---..", 9: "----." };
function railFence(s, rails) {
    const rows = Array.from({ length: rails }, () => []); let r = 0, d = 1;
    for (const c of s) { rows[r].push(c); if (rails > 1) { if (r === 0) d = 1; else if (r === rails - 1) d = -1; r += d; } }
    return rows.map(x => x.join("")).join("");
}
const gcd = (a, b) => b ? gcd(b, a % b) : a;
function affine(s, a, b) { return s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode(((a * (c.charCodeAt(0) - o) + b) % 26) + o); }); }
function vigenere(s, key) {
    let j = 0; key = key.toLowerCase();
    return s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; const k = key.charCodeAt(j++ % key.length) - 97; return String.fromCharCode((c.charCodeAt(0) - o + k) % 26 + o); });
}
function bacon(s) { // Bacon "Complete" alphabet (26 distinct codes), A/B
    return s.toUpperCase().replace(/[^A-Z]/g, "").split("").map(c => (c.charCodeAt(0) - 65).toString(2).padStart(5, "0").replace(/0/g, "A").replace(/1/g, "B")).join(" ");
}
const WORDS = ["secret", "malware", "cipher", "lemon", "orange", "dragon", "falcon", "tiger", "shadow", "kernel", "packet", "beacon"];

export const TRANSFORMS = [
    // ---- encodings
    { id: "base64", kind: "enc", make: b => T(Buffer.from(b).toString("base64")) },
    { id: "base64url", kind: "enc", make: b => T(Buffer.from(b).toString("base64url")) },
    { id: "base32", kind: "enc", make: b => T(base32(b)) },
    { id: "base58", kind: "enc", max: 600, make: b => T(baseN(b, B58)) },
    { id: "base62", kind: "enc", max: 600, make: b => T(base62(b)), noLeadingZero: true },
    { id: "base45", kind: "enc", make: b => T(base45(b)) },
    { id: "ascii85", kind: "enc", make: b => T("<~" + ascii85(b) + "~>") },
    { id: "base85", kind: "enc", make: b => T(ascii85(b)) },
    { id: "hex", kind: "enc", make: b => T(Buffer.from(b).toString("hex")) },
    { id: "hex-spaced", kind: "enc", make: b => T([...b].map(x => x.toString(16).padStart(2, "0")).join(" ")) },
    { id: "hex-0x", kind: "enc", make: b => T([...b].map(x => "0x" + x.toString(16).padStart(2, "0")).join(",")) },
    { id: "hex-escaped", kind: "enc", make: b => T([...b].map(x => "\\x" + x.toString(16).padStart(2, "0")).join("")) },
    { id: "binary", kind: "enc", max: 800, make: b => T([...b].map(x => x.toString(2).padStart(8, "0")).join(" ")) },
    { id: "octal", kind: "enc", max: 800, make: b => T([...b].map(x => x.toString(8).padStart(3, "0")).join(" ")) },
    { id: "decimal", kind: "enc", max: 800, make: b => T([...b].join(" ")) },
    { id: "decimal-comma", kind: "enc", max: 800, make: b => T([...b].join(",")) },
    { id: "url", kind: "enc", make: b => T([...b].map(x => "%" + x.toString(16).padStart(2, "0").toUpperCase()).join("")) },
    { id: "html-dec", kind: "enc", textOnly: true, make: b => T([...S(b)].map(c => `&#${c.charCodeAt(0)};`).join("")) },
    { id: "html-hex", kind: "enc", textOnly: true, make: b => T([...S(b)].map(c => `&#x${c.charCodeAt(0).toString(16)};`).join("")) },
    { id: "unicode-escape", kind: "enc", textOnly: true, make: b => T([...S(b)].map(c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("")) },
    // RFC 2045 quoted-printable: "=", control and 8-bit bytes must be encoded; printable characters may be (here: 40 % of letters/spaces)
    { id: "quoted-printable", kind: "enc", textOnly: true, make: (b, r) => T([...S(b)].map(c => /[^ -<>-~]/.test(c) || (/[A-Za-z ]/.test(c) && r() < 0.4) ? "=" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0") : c).join("")) },
    // ---- compression
    { id: "gzip", kind: "comp", make: b => zlib.gzipSync(b) },
    { id: "zlib", kind: "comp", make: b => zlib.deflateSync(b) },
    { id: "deflate-raw", kind: "comp", make: b => zlib.deflateRawSync(b) },
    { id: "lzstring-b64", kind: "comp", textOnly: true, make: b => T(LZString.compressToBase64(S(b))) },
    // ---- classical / transformations (text)
    { id: "reverse", kind: "text", make: b => Buffer.from(b).reverse() },
    { id: "rot13", kind: "text", textOnly: true, make: b => T(rotN(S(b), 13)) },
    { id: "rotN", kind: "text", textOnly: true, make: (b, r) => T(rotN(S(b), 1 + Math.floor(r() * 25))) },
    { id: "rot47", kind: "text", textOnly: true, make: b => T(rot47(S(b))) },
    { id: "atbash", kind: "text", textOnly: true, make: b => T(atbash(S(b))) },
    // ---- byte transforms
    { id: "xor1", kind: "xor", make: (b, r) => { const k = 1 + Math.floor(r() * 254); return Buffer.from(Buffer.from(b).map(x => x ^ k)); } },
];

/** Ciphers applied to English plaintext first (crackable without a key, like typical CTF/test strings). */
export const CLASSICAL = [
    { id: "caesar", make: (s, r) => rotN(s, 1 + Math.floor(r() * 25)) },
    { id: "rot13-digits", make: s => rotN(s, 13, false) },
    { id: "atbash", make: s => atbash(s) },
    { id: "affine", make: (s, r) => { const as = [3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]; const a = as[Math.floor(r() * as.length)]; return affine(s, a, Math.floor(r() * 26)); } },
    { id: "vigenere", minLen: 120, make: (s, r) => vigenere(s, WORDS[Math.floor(r() * WORDS.length)]) },
    { id: "railfence", make: (s, r) => railFence(s, 2 + Math.floor(r() * 4)) },
    { id: "reverse-words", make: s => [...s].reverse().join("") },
    { id: "xor-repeating", minLen: 120, make: (s, r) => { const key = WORDS[Math.floor(r() * WORDS.length)]; return S(Buffer.from(Buffer.from(s, "latin1").map((x, i) => x ^ key.charCodeAt(i % key.length)))); } },
    { id: "morse", lossy: true, make: s => s.toUpperCase().split(" ").map(w => [...w].filter(c => MORSE[c]).map(c => MORSE[c]).join(" ")).filter(Boolean).join(" / ") },
    { id: "a1z26", lossy: true, make: s => s.toUpperCase().replace(/[^A-Z ]/g, "").split(/ +/).filter(Boolean).map(w => [...w].map(c => c.charCodeAt(0) - 64).join("-")).join(" ") },
    { id: "bacon", lossy: true, make: s => bacon(s) },
    { id: "binary-7bit-words", make: s => [...s].map(c => c.charCodeAt(0).toString(2).padStart(8, "0")).join("") },
];

/** Ciphers that need a key the user provides (tests the key field). Returns {text, key}. */
export const KEYED = [
    { id: "openssl-aes-256-cbc-pbkdf2", make: (pt, r, rnd) => { // openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -pass pass:KEY
        const pass = pickPass(r), salt = rnd(8);
        const km = crypto.pbkdf2Sync(pass, salt, 10000, 48, "sha256");
        const c = crypto.createCipheriv("aes-256-cbc", km.subarray(0, 32), km.subarray(32, 48));
        return { text: Buffer.concat([Buffer.from("Salted__"), salt, c.update(pt), c.final()]).toString("base64"), key: pass };
    } },
    { id: "openssl-aes-256-cbc-md5 (CryptoJS default)", make: (pt, r, rnd) => { // CryptoJS.AES.encrypt(text, passphrase) / openssl enc -md md5
        const pass = pickPass(r), salt = rnd(8);
        const km = evpBytesToKey(Buffer.from(pass), salt, 48, "md5");
        const c = crypto.createCipheriv("aes-256-cbc", km.subarray(0, 32), km.subarray(32, 48));
        return { text: Buffer.concat([Buffer.from("Salted__"), salt, c.update(pt), c.final()]).toString("base64"), key: pass };
    } },
    { id: "aes-128-ecb-raw-key", make: (pt, r) => { const key = pickKey16(r); const c = crypto.createCipheriv("aes-128-ecb", Buffer.from(key), null); return { text: Buffer.concat([c.update(pt), c.final()]).toString("base64"), key }; } },
    { id: "aes-256-cbc-hex-key-iv", make: (pt, r, rnd) => { const k = rnd(32), iv = rnd(16); const c = crypto.createCipheriv("aes-256-cbc", k, iv); return { text: Buffer.concat([c.update(pt), c.final()]).toString("hex"), key: `${k.toString("hex")}\n${iv.toString("hex")}` }; } },
    { id: "aes-256-cbc-iv-prefixed", make: (pt, r, rnd) => { const k = rnd(32), iv = rnd(16); const c = crypto.createCipheriv("aes-256-cbc", k, iv); return { text: Buffer.concat([iv, c.update(pt), c.final()]).toString("base64"), key: k.toString("hex") }; } },
    { id: "aes-256-gcm-like-ctr", make: (pt, r, rnd) => { const k = rnd(32), iv = rnd(16); const c = crypto.createCipheriv("aes-256-ctr", k, iv); return { text: Buffer.concat([iv, c.update(pt)]).toString("base64"), key: k.toString("base64") }; } },
    { id: "rc4-password", make: (pt, r) => { const pass = pickPass(r); return { text: Buffer.from(rc4(Buffer.from(pass), pt)).toString("base64"), key: pass }; } },
    { id: "xor-password", make: (pt, r) => { const pass = pickPass(r); return { text: Buffer.from(pt.map((x, i) => x ^ pass.charCodeAt(i % pass.length))).toString("hex"), key: pass }; } },
    { id: "vigenere-key", make: (pt, r) => { const key = WORDS[Math.floor(r() * WORDS.length)]; return { text: vigenere(pt.toString("latin1"), key), key }; } },
    { id: "chacha20-hex", make: async (pt, r, rnd) => { const { chacha20 } = await import("@noble/ciphers/chacha.js"); const k = rnd(32), n = rnd(12); return { text: Buffer.from(chacha20(k, n, pt)).toString("base64"), key: `${k.toString("hex")}\n${n.toString("hex")}` }; } },
    { id: "fernet", make: (pt, r, rnd) => { // https://github.com/fernet/spec
        const key = rnd(32), sign = key.subarray(0, 16), enc = key.subarray(16), iv = rnd(16);
        const ts = Buffer.alloc(8); ts.writeBigUInt64BE(1700000000n);
        const c = crypto.createCipheriv("aes-128-cbc", enc, iv);
        const body = Buffer.concat([Buffer.from([0x80]), ts, iv, c.update(pt), c.final()]);
        const mac = crypto.createHmac("sha256", sign).update(body).digest();
        return { text: Buffer.concat([body, mac]).toString("base64url"), key: key.toString("base64url") };
    } },
    { id: "des-ecb-text-key", make: (pt, r) => { const key = pickPass(r).padEnd(8, "x").slice(0, 8); try { const c = crypto.createCipheriv("des-ecb", Buffer.from(key), null); return { text: Buffer.concat([c.update(pt), c.final()]).toString("base64"), key }; } catch { return null; } } },
    { id: "blowfish-cbc", make: (pt, r, rnd) => { const k = rnd(16), iv = rnd(8); try { const c = crypto.createCipheriv("bf-cbc", k, iv); return { text: Buffer.concat([c.update(pt), c.final()]).toString("base64"), key: `${k.toString("hex")}\n${iv.toString("hex")}` }; } catch { return null; } } },
];

const PASSES = ["infected", "P@ssw0rd!", "letmein123", "S3cr3tK3y", "hunter2", "correcthorse", "malware2026", "Spring2026!", "qwerty!@#", "dragonfly"];
function pickPass(r) { return PASSES[Math.floor(r() * PASSES.length)]; }
function pickKey16(r) { return ["0123456789abcdef", "YELLOW SUBMARINE", "ThisIsA16ByteKey", "aaaaBBBBccccDDDD"][Math.floor(r() * 4)]; }
export function evpBytesToKey(pass, salt, len, hash) {
    let d = Buffer.alloc(0), prev = Buffer.alloc(0);
    while (d.length < len) { prev = crypto.createHash(hash).update(Buffer.concat([prev, pass, salt])).digest(); d = Buffer.concat([d, prev]); }
    return d.subarray(0, len);
}
function rc4(key, data) {
    const s = [...Array(256).keys()]; let j = 0;
    for (let i = 0; i < 256; i++) { j = (j + s[i] + key[i % key.length]) & 255; [s[i], s[j]] = [s[j], s[i]]; }
    const out = Buffer.alloc(data.length);
    for (let n = 0, i = 0, k = 0; n < data.length; n++) { i = (i + 1) & 255; k = (k + s[i]) & 255; [s[i], s[k]] = [s[k], s[i]]; out[n] = data[n] ^ s[(s[i] + s[k]) & 255]; }
    return out;
}
export { gcd };
