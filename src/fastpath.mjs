/**
 * Fast path: a native JavaScript search over layered encodings.
 *
 * Multi-layer strings ("hex of base85 of zlib of ROT47 of …") are solved best by trying every
 * decoder whose alphabet fits at every layer, very quickly, and following the chain that keeps
 * producing recognisable data. Running each guess through CyberChef would be far too slow, so
 * the decoders here are small JavaScript equivalents of CyberChef operations. The chain found is
 * then translated into a CyberChef recipe and executed by CyberChef, so the result is always
 * CyberChef's own output (a JS/CyberChef mismatch simply fails verification).
 */
import zlib from "node:zlib";
import { createRequire } from "node:module";
import { printableRatio, languageScore, latin1, detectFileType } from "./analyze.mjs";
import { crackVigenere, crackAffine, railFenceCandidates, crackRepeatingXor, crackRepeatingAdd, LOSSY_DECODERS } from "./classical.mjs";

const require = createRequire(import.meta.url);
let LZ = null;
try { LZ = require("lz-string"); } catch { /* optional */ }

const op = (name, args) => ({ op: name, args });
const S = b => latin1(b);
const B = s => Buffer.from(s, "latin1");
const strip = s => s.replace(/\s+/g, "");

// ---------------- base-N helpers ----------------
function bigDecode(str, alphabet, leadingZeros) {
    const map = new Map([...alphabet].map((c, i) => [c, BigInt(i)]));
    let n = 0n; const base = BigInt(alphabet.length);
    for (const c of str) { const v = map.get(c); if (v === undefined) return null; n = n * base + v; }
    let hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
    let out = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
    if (leadingZeros) { let z = 0; for (const c of str) { if (c === alphabet[0]) z++; else break; } out = Buffer.concat([Buffer.alloc(z), out]); }
    return out;
}
function b32(s) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; s = s.replace(/=+$/, "");
    let bits = ""; for (const c of s) { const v = A.indexOf(c); if (v < 0) return null; bits += v.toString(2).padStart(5, "0"); }
    const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(out);
}
function b45(s) {
    const A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"; const out = [];
    for (let i = 0; i < s.length; i += 3) {
        const c = A.indexOf(s[i]), d = A.indexOf(s[i + 1]);
        if (c < 0 || d < 0) return null;
        if (i + 2 < s.length) { const e = A.indexOf(s[i + 2]); if (e < 0) return null; const n = c + d * 45 + e * 2025; if (n > 65535) return null; out.push(n >> 8, n & 255); }
        else { const n = c + d * 45; if (n > 255) return null; out.push(n); }
    }
    return Buffer.from(out);
}
function a85(s) {
    s = s.replace(/^<~/, "").replace(/~>$/, "").replace(/\s+/g, "");
    const out = []; let i = 0;
    while (i < s.length) {
        if (s[i] === "z") { out.push(0, 0, 0, 0); i++; continue; }
        const chunk = s.slice(i, i + 5); i += 5;
        if (/[^!-u]/.test(chunk)) return null;
        const pad = 5 - chunk.length, full = chunk + "u".repeat(pad);
        let n = 0; for (const c of full) n = n * 85 + (c.charCodeAt(0) - 33);
        if (n > 0xffffffff) return null;
        const bytes = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
        out.push(...bytes.slice(0, 4 - pad));
    }
    return Buffer.from(out);
}
const rot = (s, k) => s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - o + k) % 26 + o); });
const rot47 = s => s.replace(/[!-~]/g, c => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)));
const atbash = s => s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode(25 - (c.charCodeAt(0) - o) + o); });
const safe = f => { try { const r = f(); return r && r.length ? r : null; } catch { return null; } };

// ---------------- decoders ----------------
const B58A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B62A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
export const DECODERS = [
    { id: "From Base64", fits: (t, n) => n.length >= 4 && /^[A-Za-z0-9+/]+={0,3}$/.test(n) && n.replace(/=+$/, "").length % 4 !== 1, run: (t, n) => Buffer.from(n, "base64"), ops: () => [op("From Base64", ["A-Za-z0-9+/=", true, false])] },
    { id: "From Base64 (URL-safe)", fits: (t, n) => n.length >= 4 && /^[A-Za-z0-9_-]+={0,2}$/.test(n) && /[-_]/.test(n), run: (t, n) => Buffer.from(n, "base64url"), ops: () => [op("From Base64", ["A-Za-z0-9-_", true, false])] },
    { id: "From Base32", fits: (t, n) => n.length >= 8 && /^[A-Z2-7]+=*$/.test(n), run: (t, n) => b32(n), ops: () => [op("From Base32", ["A-Z2-7=", true])] },
    { id: "From Base58", fits: (t, n) => n.length >= 4 && n.length <= 1200 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(n), run: (t, n) => bigDecode(n, B58A, true), ops: () => [op("From Base58", [B58A, true])] },
    { id: "From Base62", fits: (t, n) => n.length >= 4 && n.length <= 1200 && /^[0-9A-Za-z]+$/.test(n), run: (t, n) => bigDecode(n, B62A, false), ops: () => [op("From Base62", ["0-9A-Za-z"])] },
    { id: "From Base45", fits: t => t.length >= 3 && /^[0-9A-Z $%*+\-./:]+$/.test(t) && /[ $%*+\-./:]/.test(t), run: t => b45(t), ops: () => [op("From Base45", ["0-9A-Z $%*+\\-./:", true])] },
    { id: "From Base85", fits: (t, n) => n.length >= 5 && /^(<~)?[!-uz]+(~>)?$/.test(n), run: (t, n) => a85(n), ops: () => [op("From Base85", ["!-u", true, "z"])] },
    { id: "From Hex", fits: (t, n) => n.length >= 2 && (/^([0-9a-fA-F]{2})+$/.test(n) || /^((0x|\\x)[0-9a-fA-F]{2}[,\s]*)+$/i.test(t.trim()) || /^([0-9a-fA-F]{2}[\s:,;-])+[0-9a-fA-F]{2}$/.test(t.trim())), run: (t, n) => Buffer.from(n.replace(/0x|\\x|[,:;-]/gi, ""), "hex"), ops: () => [op("From Hex", ["Auto"])] },
    { id: "From Binary", fits: (t, n) => n.length >= 8 && /^[01]+$/.test(n) && n.length % 8 === 0, run: (t, n) => Buffer.from(n.match(/.{8}/g).map(x => parseInt(x, 2))), ops: t => [op("From Binary", [/\s/.test(t.trim()) ? "Space" : "None", 8])] },
    { id: "From Octal", fits: t => /^[0-7]{1,3}(\s+[0-7]{1,3})+$/.test(t.trim()) && !/^[01\s]+$/.test(t.trim()), run: t => { const v = t.trim().split(/\s+/).map(x => parseInt(x, 8)); return v.every(x => x < 256) ? Buffer.from(v) : null; }, ops: () => [op("From Octal", ["Space"])] },
    { id: "From Decimal", fits: t => /^\d{1,3}([\s,;]+\d{1,3})+$/.test(t.trim()), run: t => { const v = t.trim().split(/[\s,;]+/).map(Number); return v.every(x => x < 256) ? Buffer.from(v) : null; }, ops: t => [op("From Decimal", [t.includes(",") ? "Comma" : t.includes(";") ? "Semi-colon" : /\n/.test(t.trim()) ? "Line feed" : "Space", false])] },
    { id: "URL Decode", fits: t => (c => c >= 2 && c * 100 >= t.length)((t.match(/%[0-9a-fA-F]{2}/g) || []).length), run: t => safe(() => B(unescape(t))), ops: () => [op("URL Decode", [true])] },
    { id: "From HTML Entity", fits: t => (t.match(/&(#x[0-9a-f]+|#\d+|[a-z]{2,8});/gi) || []).length >= 2, run: t => B(t.replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCharCode(parseInt(h, 16) & 255)).replace(/&#(\d+);/g, (m, d) => String.fromCharCode(+d & 255)).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&amp;/g, "&")), ops: () => [op("From HTML Entity", [])] },
    { id: "Unescape Unicode Characters", fits: t => (t.match(/\\u[0-9a-fA-F]{4}/g) || []).length >= 2, run: t => B(t.replace(/\\u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16) & 255))), ops: () => [op("Unescape Unicode Characters", ["\\u"])] },
    { id: "From Quoted Printable", fits: t => (c => c >= 3 && (c * 60 >= t.length || /=\r?\n/.test(t)))((t.match(/=[0-9A-F]{2}/g) || []).length) && !/^[A-Za-z0-9+/]+={0,2}$/.test(strip(t)), run: t => B(t.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)))), ops: () => [op("From Quoted Printable", [])] },
    { id: "LZString Decompress", fits: (t, n) => !!LZ && n.length >= 8 && /^[A-Za-z0-9+/]+=*$/.test(n), run: (t, n) => { const r = LZ.decompressFromBase64(n); return r ? B(r) : null; }, ops: () => [op("LZString Decompress", ["Base64"])] },
];
for (const d of LOSSY_DECODERS) DECODERS.push({ id: d.id, fits: t => d.fits(t), run: t => B(d.run(t)), ops: t => d.ops(t) });

const BIN_DECODERS = [
    { id: "Gunzip", fits: b => b[0] === 0x1f && b[1] === 0x8b, run: b => zlib.gunzipSync(b, { maxOutputLength: 64 << 20 }), ops: () => [op("Gunzip", [])] },
    { id: "Zlib Inflate", fits: b => b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(b[1]), run: b => zlib.inflateSync(b, { maxOutputLength: 64 << 20 }), ops: () => [op("Zlib Inflate", [0, 0, "Adaptive", false, false])] },
    { id: "Raw Inflate", fits: b => b.length >= 4, run: b => zlib.inflateRawSync(b, { maxOutputLength: 64 << 20 }), ops: () => [op("Raw Inflate", [0, 0, "Adaptive", false, false])] },
];
// reversible text transforms (applied to text that isn't readable yet)
const TEXT_TX = [
    { id: "Reverse", run: t => [...t].reverse().join(""), ops: () => [op("Reverse", ["Character"])] },
    { id: "ROT47", run: t => rot47(t), ops: () => [op("ROT47", [47])] },
    { id: "Atbash Cipher", run: t => atbash(t), ops: () => [op("Atbash Cipher", [])] },
    ...Array.from({ length: 25 }, (_, i) => ({ id: `ROT13 (shift ${i + 1})`, run: t => rot(t, i + 1), ops: () => [op("ROT13", [true, true, false, i + 1])] })),
];


// ---------------- code-point offset ("each character is one byte + a fixed offset") ----------------
// e.g. CJK obfuscation: byte b is written as the character U+4E00 + b. All characters then sit in a
// window of at most 256 code points, which natural text in any script practically never does.
// CyberChef recipe: To Charcode (hex) -> keep the low byte of each code -> From Hex -> SUB low byte of the offset.
export function codePointOffset(b, max = 3) {
    if (b.length < 16 || b.length > 4 << 20) return [];
    // every character >= U+0100 means every UTF-8 sequence starts with a lead byte >= 0xC4 (cheap pre-check)
    if (b[0] < 0xc4 || b[b.length >> 1] < 0x80) return [];
    const s = b.toString("utf8").replace(/\s+$/, "");
    if (s.includes("\uFFFD")) return [];
    const cps = Array.from(s, c => c.codePointAt(0));
    if (cps.length < 8 || cps.some(c => c < 0x100)) return [];
    let lo = Infinity, hi = -Infinity;
    for (const c of cps) { if (c < lo) lo = c; if (c > hi) hi = c; }
    if (hi - lo > 255) return [];
    const sample = cps.length > 20000 ? cps.slice(0, 20000) : cps;
    const res = [];
    // every possible low byte of the offset whose result keeps all values inside one byte
    for (let base = Math.max(0, hi - 255); base <= lo; base++) {
        const out = Buffer.from(sample.map(c => c - base));
        // readable text wins; then data a strict decoder accepts (Base64, hex, ...) or a binary container
        const txt = isText(out);
        const sc = readable(out) * 2 + (txt ? (strictStructured(S(out)) ? 1 : 0) + 0.2 : (structured(out) || inflates(out) ? 1 : 0));
        // natural Thai or kana text also fits in one window: only convincing results count
        const ok = txt ? readable(out) >= 0.45 || strictStructured(S(out)) : sc >= 1 || !!detectFileType(out)?.final;
        if (ok) res.push({ base, sc: sc + (detectFileType(out)?.final ? 2 : 0) });
    }
    res.sort((a, b) => b.sc - a.sc);
    // natural Thai or kana text also fits in one window: only offer decodes whose result is convincing
    return res.slice(0, max).map(({ base }) => {
        const k = base & 0xff, hex = "0x" + base.toString(16).toUpperCase();
        const ops = [op("To Charcode", ["Space", 16]), op("Find / Replace", [{ option: "Regex", string: "[0-9a-f]*([0-9a-f]{2})( |$)" }, "$1$2", true, false, true, false]), op("From Hex", ["Auto"])];
        if (k) ops.push(op("SUB", [{ option: "Hex", string: k.toString(16).padStart(2, "0") }]));
        return { id: `Code-point offset ${hex}`, ops, out: Buffer.from(cps.map(c => c - base)) };
    });
}

// ---------------- scoring ----------------
const CLEAN = /[A-Za-z0-9 \t\r\n.,:;\/\\_\-'"=()]/;
/** language score plus share of text-typical characters (separates the right rotation from near misses) */
function textQuality(s) {
    if (!s.length) return 0;
    let c = 0;
    for (const ch of s) if (CLEAN.test(ch)) c++;
    return letterAdjusted(s) + 0.5 * c / s.length;
}
/** how narrow the alphabet of the encoding that fits is (hex is far more specific than Base64) */
function spec(t) {
    const n = strip(t);
    const fit = id => DECODERS.find(d => d.id === id)?.fits(t, n);
    if (fit("From Hex") || fit("From Binary") || fit("From Octal") || fit("From Decimal") || fit("From HTML Entity") || fit("Unescape Unicode Characters") || fit("URL Decode")) return 5;
    if (fit("From Base32")) return 4;
    if (fit("From Base64") || fit("From Base64 (URL-safe)") || fit("From Base45")) return 3;
    if (fit("From Base58") || fit("From Base62")) return 2;
    return fit("From Base85") ? 1 : 0;
}
/** one level of look-ahead: how good is the best thing a decoder makes of this? */
export function lookahead(x) {
    const full = x;
    const truncated = x.length > 600;
    if (truncated) x = x.subarray(0, 600);
    let best = readable(x) + (structured(x) ? 0.3 : 0);
    if (BIN_DECODERS.slice(0, 2).some(d => d.fits(x))) return best + 1.5;
    if (!isText(x)) return inflates(x, truncated) ? 1.4 : best;
    const t = S(x), n = strip(t);
    for (const d of DECODERS) {
        if (truncated && (d.id === "From Base58" || d.id === "From Base62") && full.length > 1200) continue; // not prefix-stable: decode it whole when small enough
        if ((d.id === "From Base58" || d.id === "From Base62") && truncated) { const ft = S(full), fn = strip(ft); if (d.fits(ft, fn)) { const r = safe(() => d.run(ft, fn)); if (r && r.length) { const rb = Buffer.from(r).subarray(0, 600); const v = 0.5 + readable(rb) + (structured(rb) ? 0.6 : 0); if (v > best) best = v; } } continue; }
        if (!d.fits(t, n)) continue;
        const r = safe(() => d.run(t, n));
        if (!r || !r.length) continue;
        const rb = Buffer.from(r);
        const v = 0.5 + readable(rb) + (structured(rb) ? 0.6 : 0) + (BIN_DECODERS.slice(0, 2).some(z => z.fits(rb)) || (!isText(rb) && inflates(rb, truncated)) ? 0.9 : 0);
        if (v > best) best = v;
    }
    return best;
}
/** single-byte XOR keys worth trying (best 2 by structure + look-ahead) */
export function xorKeys(b, fromText = false) {
    const sample = b.subarray(0, 1024);
    const cands = [];
    for (let k = 1; k < 256; k++) {
        if ((k & 15) === 0 && late()) break;
        const x = Buffer.from(sample.map(v => v ^ k));
        let sc = (structured(x) ? 1 : 0) + (isText(x.subarray(0, 512)) ? readable(x.subarray(0, 512)) : 0);
        if (sc < 0.6 && isText(x) && structured(Buffer.from(x).reverse())) sc = 0.9; // XOR'ed reversed encoding
        if (sc < 0.6 && !isText(x) && !fromText && inflates(Buffer.from(b.map(v => v ^ k)))) sc = 1.2; // XOR'ed raw Deflate
        if (sc > 0.4) cands.push({ k, sc });
    }
    if (!cands.length) return [];
    cands.sort((a, c) => c.sc - a.sc);
    const la = b.subarray(0, 600);
    const top = cands.slice(0, late() ? 4 : 64).map(c => { const x = Buffer.from(la.map(v => v ^ c.k)); return { ...c, la: Math.max(lookahead(x), isText(x) ? lookahead(Buffer.from(x).reverse()) - 0.1 : 0) }; });
    // plain readable text after the XOR beats "decodes into something": most XOR keys hide text directly
    const val = c => c.sc * 0.5 + c.la + (readable(Buffer.from(la.map(v => v ^ c.k))) >= 0.45 ? 1 : 0);
    top.sort((a, c) => val(c) - val(a));
    if (fromText && top[0].sc * 0.5 + top[0].la < 1.3) return [];
    return top.slice(0, 2).map(c => c.k);
}
/** single-byte ADD (byte + k mod 256): constant-offset ciphers such as Fortra's "byte - 65, reversed" layer */
export function addKeys(b) {
    const sample = b.subarray(0, 1024);
    const head = sample.subarray(0, 64);
    const cands = [];
    for (let k = 1; k < 256; k++) {
        if ((k & 15) === 0 && late()) break;
        // cheap pre-filter without allocating: the first bytes must be text, or start a known header
        const h0 = (head[0] + k) & 255;
        if (![0x4d, 0x1f, 0x78, 0x50, 0x25, 0x7f].includes(h0)) {
            let p = 0;
            for (let i = 0; i < head.length; i++) { const v = (head[i] + k) & 255; if ((v >= 32 && v < 127) || v === 9 || v === 10 || v === 13) p++; }
            if (p < head.length * 0.9) continue;
        }
        const x = Buffer.from(sample.map(v => (v + k) & 255));
        let sc = 0;
        const ft = detectFileType(x);
        if (ft && ft.final) sc = 2;
        else if (isText(x)) {
            // clearly readable text (also reversed), or an encoding whose next layer is meaningful: shifted bytes
            // turn into "almost text" far too easily, so weak results are not kept
            const rx = Buffer.from(x).reverse();
            const rd = Math.max(readable(x), readable(rx));
            sc = rd >= 0.55 ? rd + 0.5 : Math.max(lookahead(x), lookahead(rx)) >= 1.3 ? 1 : 0;
        } else if (BIN_DECODERS.slice(0, 2).some(d => d.fits(x) && safe(() => d.run(Buffer.from(b.map(v => (v + k) & 255)))))) sc = 1.5; // gzip / zlib that really decompresses
        if (sc >= 1) cands.push({ k, sc });
    }
    cands.sort((a, c) => c.sc - a.sc);
    return cands.slice(0, 2).map(c => c.k);
}
/** structured, ignoring decoders whose alphabets accept almost any printable text */
function strictStructured(t) {
    const n = strip(t);
    return DECODERS.some(d => !["From Base85", "From Base45", "From Base58", "From Base62", "LZString Decompress", "From Quoted Printable"].includes(d.id) && d.fits(t, n));
}
function inflates(b, partial = false) {
    // a prefix (look-ahead) may end mid-stream: then flush what decodes; whole data must inflate completely
    try { const r = zlib.inflateRawSync(b, partial ? { maxOutputLength: 64 << 20, finishFlush: zlib.constants.Z_SYNC_FLUSH } : { maxOutputLength: 64 << 20 }); return r.length >= 8 && (isText(r) || structured(r)); } catch { return false; }
}
const isText = b => printableRatio(b, Math.min(b.length, 8192)) >= 0.97;
const RCACHE = new WeakMap();
export function readable(b) {
    let v = RCACHE.get(b);
    if (v !== undefined) return v;
    const ft = detectFileType(b);
    v = ft && ft.final ? 1 : !isText(b) ? 0 : letterAdjusted(latin1(b, 2000));
    RCACHE.set(b, v);
    return v;
}
/** languageScore, scaled down when few characters are letters (symbol soup can hit short dictionary words) */
function letterAdjusted(t) {
    const ls = languageScore(t);
    const nonSpace = t.replace(/\s/g, "").length || 1;
    const share = (t.match(/[A-Za-z]/g) || []).length / nonSpace;
    let v = share >= 0.55 ? ls : ls * share / 0.55;
    if (v > 0.3 && t.length >= 60) {
        // one short token repeated everywhere ("_node_node…") is filler, not language
        const sm = t.slice(0, 2000), cnt = new Map();
        for (let i = 0; i + 5 <= sm.length; i++) { const g = sm.substr(i, 5); cnt.set(g, (cnt.get(g) || 0) + 1); }
        const top = Math.max(...cnt.values());
        if (top * 5 / sm.length > 0.3) v *= 0.3;
    }
    if (v > 0.3 && t.length >= 24) {
        // a short unit repeated over and over (typical of a wrong XOR key over encoded data) is not language
        const sample = t.slice(0, 1500);
        const ratio = zlib.deflateRawSync(Buffer.from(sample, "latin1")).length / sample.length;
        if (ratio < 0.25) v *= ratio / 0.25;
    }
    return v;
}
/** Does some decoder accept this as a valid encoding (cheap structural check)? */
export function structured(b) {
    if (BIN_DECODERS[0].fits(b) || BIN_DECODERS[1].fits(b)) return true;
    if (!isText(b)) return false;
    const t = S(b), n = strip(t);
    return DECODERS.some(d => d.id !== "From Base62" && d.id !== "From Base58" && d.fits(t, n));
}

/**
 * Best-first search. Returns up to `max` chains [{ops, steps:[{id}], out, score}] that end in readable output.
 */
let DEADLINE = Infinity; // expensive loops inside one expansion stop here too (slow machines, browsers)
const late = () => Date.now() > DEADLINE;
export function fastSolve(input, { timeMs = 2500, maxDepth = 12, max = 3 } = {}) {
    const t0 = Date.now();
    DEADLINE = t0 + timeMs;
    const start = Buffer.from(input);
    const startRead = readable(start);
    const seen = new Set();
    const key = b => b.length + ":" + b.subarray(0, 64).toString("hex") + b.subarray(-32).toString("hex");
    let frontier = [{ b: start, steps: [], pr: 0 }];
    const solutions = [], weak = [];
    let stopAt = -1;
    seen.add(key(start));
    for (let depth = 0; depth < maxDepth && frontier.length && Date.now() - t0 < timeMs; depth++) {
        const next = [];
        for (const node of frontier) {
            if (Date.now() - t0 > timeMs) break;
            const kids = expand(node).sort((a, b) => b.pr - a.pr);
            let kept = 0;
            for (const child of kids) {
                const k = key(child.b);
                if (seen.has(k)) continue;
                seen.add(k);
                const r = readable(child.b);
                const bigEnough = child.b.length >= Math.min(16, start.length / 4);
                const lastId = child.steps[child.steps.length - 1].id;
                if (LOSSY_IDS.has(lastId) && child.b.length >= 10 && /^[A-Za-z0-9 ?]+$/.test(S(child.b))) { solutions.push({ ...child, score: 0.45 + languageScore(S(child.b).toLowerCase()) }); continue; }
                if ((bigEnough && r >= Math.max(0.45, startRead + 0.08)) || (detectFileType(child.b)?.final && !detectFileType(start)?.final)) {
                    solutions.push({ ...child, score: r });
                    continue;
                }
                // printable text no decoder accepts any more: a plausible end point (short commands score low on language)
                if (isText(child.b) && child.b.length >= 12 && !structured(child.b) && r >= 0.2 && r > startRead && child.steps.filter(st => isTx(st.id)).length <= 2) weak.push({ ...child, score: r * 0.8 });
                if (kept++ < 6) next.push(child); // keep the beam diverse: a few children per parent

            }
        }
        // keep the most promising nodes: structured data first, fewer text-transforms, shorter
        next.sort((a, b) => b.pr - a.pr);
        frontier = next.slice(0, 40);
        if (process.env.FP_DEBUG) console.error("depth", depth, "frontier", frontier.length, "of", next.length, frontier.slice(0, 8).map(x => x.steps.map(s => s.id).join(">") + ":" + x.pr.toFixed(2)).join(" | "), "ms", Date.now() - t0);
        if (solutions.length >= max) break;
        // a clean answer was found: one more level for alternatives, then stop
        if (solutions.some(x => x.score >= 0.6)) { if (stopAt < 0) stopAt = depth + 1; else if (depth >= stopAt) break; }
    }
    if (solutions.length < max) solutions.push(...weak.sort((a, b) => b.score - a.score).slice(0, max - solutions.length));
    // many transform steps make a chain less believable
    for (const x of solutions) x.score -= 0.03 * Math.max(0, x.steps.filter(st => isTx(st.id)).length - 1);
    solutions.sort((a, b) => b.score - a.score || a.steps.length - b.steps.length);
    return solutions.slice(0, max).map(s => ({ ops: s.steps.flatMap(x => x.ops), steps: s.steps, out: s.b, score: s.score }));
}

const LOSSY_IDS = new Set(LOSSY_DECODERS.map(d => d.id));
const isTx = id => /^(ROT|Atbash|XOR|ADD|Reverse)/.test(id);
export function expand(node) {
    const out = [];
    const b = node.b;
    // at most two transforms (ROT / Atbash / XOR / Reverse) in a row: longer runs only fit noise
    let trail = 0;
    for (let i = node.steps.length - 1; i >= 0 && isTx(node.steps[i].id); i--) trail++;
    const txOk = trail < 2;
    const push = (dec, res, extra = 0) => {
        if (!res || !res.length || res.length > 64 << 20) return;
        const nb = Buffer.from(res);
        if (nb.equals(b)) return;
        const st = structured(nb) ? (isText(nb) && !strictStructured(S(nb)) ? 0.8 : 2) : 0, rd = readable(nb);
        out.push({ b: nb, steps: [...node.steps, { id: dec.id, ops: dec.ops(dec._t) }], pr: st + rd * 3 + extra - node.steps.length * 0.1 });
    };
    // one character per byte, shifted into another Unicode block (e.g. CJK + 0x4E00)
    for (const c of codePointOffset(b, 3)) push({ id: c.id, ops: () => c.ops }, c.out, 1);
    // binary containers
    for (const d of BIN_DECODERS) if (d.fits(b)) push(d, safe(() => d.run(b)), 1);
    if (!isText(b)) {
        // single-byte XOR that turns binary into structured / readable data
        const lastXor = /^XOR/.test(node.steps.at(-1)?.id || ""); // XOR after XOR is just another XOR
        if (b.length >= 8 && txOk && !lastXor) for (const k of xorKeys(b)) push({ id: `XOR 0x${k.toString(16)}`, ops: () => [op("XOR", [{ option: "Hex", string: k.toString(16).padStart(2, "0") }, "Standard", false])] }, Buffer.from(b.map(v => v ^ k)));
        // single-byte ADD / SUB (XOR's arithmetic cousin)
        const lastAdd = /^ADD/.test(node.steps.at(-1)?.id || "");
        if (b.length >= 8 && txOk && !lastAdd) for (const k of addKeys(b)) push({ id: `ADD 0x${k.toString(16)}`, ops: () => [op("ADD", [{ option: "Hex", string: k.toString(16).padStart(2, "0") }])] }, Buffer.from(b.map(v => (v + k) & 255)));
        if (b.length >= 8) {
            // repeating-key ADD (key recovered from the data itself)
            if (txOk && b.length >= 48 && !late() && !lastAdd) { const c = crackRepeatingAdd(b); if (c && (readable(c.out) >= 0.55 || (isText(c.out) && strictStructured(S(c.out)) && lookahead(c.out) >= 1.0))) push({ id: c.id, ops: () => c.ops }, c.out, 0.5); }
            // repeating-key XOR (key recovered from the data itself)
            if (txOk && b.length >= 40 && !late()) { const c = crackRepeatingXor(b); if (c && readable(c.out) >= 0.5) push({ id: c.id, ops: () => c.ops }, c.out, 0.5); }
            // bytes stored backwards (reversed compressed data)
            const rb = Buffer.from(b).reverse();
            if (txOk && (structured(rb) || inflates(rb))) push({ id: "Reverse", ops: () => [op("Reverse", ["Byte"])] }, rb, 0.5);
        }
        return out;
    }
    const t = S(b), n = strip(t);
    for (const d of DECODERS) {
        if (!d.fits(t, n)) continue;
        const r = safe(() => d.run(t, n));
        if (r) push({ ...d, _t: t, ops: () => d.ops(t) }, r, 0.5);
    }
    // text transforms: only keep those that make the text decodable or readable (one level of look-ahead)
    const before = readable(b);
    // expensive look-ahead only when no decoder made anything useful of this text
    const needLook = !strictStructured(t) && !out.some(c => structured(c.b) || readable(c.b) > 0.3 || (!isText(c.b) && inflates(c.b)));
    // a decoder already turned this into readable text or clean data: transforms would only add noise
    const goodDecode = out.some(c => readable(c.b) >= 0.45 || (isText(c.b) && strictStructured(S(c.b))) || BIN_DECODERS.slice(0, 2).some(z => z.fits(c.b)) || (!isText(c.b) && detectFileType(c.b)?.final));
    for (const tx of txOk && !goodDecode && !late() ? TEXT_TX : []) {
        if (node.steps.length && node.steps[node.steps.length - 1].id === tx.id) continue;
        const r = B(tx.run(t));
        if (r.equals(b)) continue;
        const st = structured(r), rd = readable(r);
        if (st && !structured(b)) { push(tx, r, 0.3); continue; }
        if (st && /^ROT|Atbash/.test(tx.id) && spec(S(r)) > spec(t) + 1) { push(tx, r, 0.6); continue; } // e.g. ROT13'd hex: "2r 65" -> "2e 65"
        if (st && (tx.id === "Reverse")) {
            // reversed encodings (e.g. reversed Base64) decode to clean data, the original doesn't
            const rt = S(r), rn = strip(rt);
            if (DECODERS.some(d => d.fits(rt, rn) && (x => x && x.length >= 8 && (structured(x) || readable(x) > 0.3 || isText(Buffer.from(x))))(safe(() => d.run(rt, rn))))) { push(tx, r, 0.4); continue; }
        }
        if (rd > before + 0.2 || (tx.id === "Reverse" && rd > before + 0.08 && rd >= 0.35)) push(tx, r, 0);
        else if (needLook && isText(r) && lookahead(r) >= 1.1) push(tx, r, 0.2);
        else if (st && /^ROT|Atbash|ROT47/.test(tx.id)) {
            // rotated Base64/hex: the rotated text must decode into something better
            const rt = S(r), rn = strip(rt);
            let okv = 0;
            for (const d of DECODERS) {
                if (!d.fits(rt, rn)) continue;
                const x = safe(() => d.run(rt, rn));
                if (!x || !x.length) continue;
                const xb = Buffer.from(x);
                let v = BIN_DECODERS.slice(0, 2).some(z => z.fits(xb)) ? 1.2 : !isText(xb) && inflates(xb) ? 1.1 : readable(xb) > 0.35 ? 0.5 + readable(xb) : structured(xb) ? 0.6 : 0;
                // second level: the decoded text is itself an encoding that decodes cleanly
                if (v > 0 && v < 1 && isText(xb) && strictStructured(S(xb.subarray(0, 600)))) v = Math.max(v, 0.8 * lookahead(xb.subarray(0, 600)));
                if (v > okv) okv = v;
            }
            if (okv) push(tx, r, 0.2 + okv);
        }
    }
    // XOR'ed text that stayed printable (small keys keep letters letters)
    if (txOk && b.length >= 8 && before < 0.45 && needLook && !out.some(c => readable(c.b) >= 0.45))
        for (const k of xorKeys(b, true)) push({ id: `XOR 0x${k.toString(16)}`, ops: () => [op("XOR", [{ option: "Hex", string: k.toString(16).padStart(2, "0") }, "Standard", false])] }, Buffer.from(b.map(v => v ^ k)));
    // classical ciphers on letter text: recover the key (Vigenère, Affine, Rail Fence) or repeating-key XOR
    const letterShare = (t.match(/[A-Za-z]/g) || []).length / Math.max(1, t.length);
    if (!late() && txOk && !goodDecode && before < 0.45 && t.length >= 30 && t.length <= 8000 && !strictStructured(t)) { // classical puzzles are short
        const q0 = textQuality(t.slice(0, 1500));
        const tries = letterShare > 0.5 ? [crackVigenere(t), crackAffine(t), ...railFenceCandidates(t, textQuality)] : [];
        if (needLook && b.length >= 40) tries.push(crackRepeatingXor(b));
        for (const c of tries) {
            if (!c) continue;
            const ob = B(c.out);
            const q = textQuality(S(ob).slice(0, 1500));
            const need = /^XOR/.test(c.id) ? 0.5 : /^Vigen/.test(c.id) ? 0.4 : 0.3; // a long recovered XOR key can force almost any text into letters
            if (q > q0 + 0.15 && readable(ob) >= need) push({ id: c.id, ops: () => c.ops }, ob, 0.6);
        }
    }
    // two text transforms in a row (e.g. ROT47 then a Caesar shift): only for text no decoder accepts
    const bestSingle = Math.max(0, ...out.map(c => readable(c.b)));
    if (!late() && txOk && bestSingle < 0.55 && t.length >= 8 && /[A-Za-z]/.test(t) && node.steps.length <= 3 && !strictStructured(t)) {
        const sample = t.slice(0, 400);
        const beforeQ = textQuality(sample);
        const bestSingleQ = Math.max(0, ...out.filter(c => isText(c.b)).map(c => textQuality(S(c.b).slice(0, 400))));
        let best = null;
        for (const a of TEXT_TX) for (const c of TEXT_TX) {
            if (a.id === c.id) continue;
            const r = c.run(a.run(sample));
            const rd = textQuality(r);
            if (rd > beforeQ + 0.2 && rd > bestSingleQ + 0.04 && (!best || rd > best.rd)) best = { a, c, rd };
        }
        if (best) push({ id: `${best.a.id} + ${best.c.id}`, ops: () => [...best.a.ops(), ...best.c.ops()] }, B(best.c.run(best.a.run(t))), 0);
    }
    return out;
}
