/**
 * Advanced detectors, learned from real malware samples:
 *  - byte / char-code arrays embedded in scripts (incl. signed Java/.NET bytes)
 *  - several encoded blobs decoded in place (CyberChef Subsection)
 *  - Base64 with junk tokens inserted, with characters substituted, or with a custom alphabet
 *  - reversed + rotated text, VBE (Microsoft Script Encoder) scripts
 *  - data carved from inside binaries (gzip/zlib/PE at an offset) and strings from PE/OLE files
 *  - AES / RC4 / DES decryption with keys and IVs harvested from the surrounding script
 * Every candidate is still executed by CyberChef and judged on its output.
 */
import crypto from "node:crypto";
import zlib from "node:zlib";
import { latin1, printableRatio, languageScore, detectFileType, entropy } from "./analyze.mjs";
import { scriptKeyCandidates, embeddedKeyCandidates, pbkdf2ConfigCandidates } from "./crypto.mjs";
import { parseUserKeys, userTextCandidates, userBinaryCandidates } from "./userkeys.mjs";

const op = (name, args) => ({ op: name, args });
const reList = (regex, fmt = "List matches") => op("Regular expression", ["User defined", regex, true, true, false, false, false, false, fmt]);
const fr = (find, repl, type = "Regex") => op("Find / Replace", [{ option: type, string: find }, repl, true, false, true, false]);
const escRe = s => s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
const B64 = "A-Za-z0-9+/=";
const B64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** quick plaintext-likeness used to pre-filter brute-force guesses in JS */
function quick(bytes) {
    if (!bytes || !bytes.length) return 0;
    const ft = detectFileType(bytes);
    if (ft) return ft.final ? 2 : 1.2;
    const p = printableRatio(bytes, 4096);
    if (p < 0.85) {
        // UTF-16 text?
        let z = 0; const n = Math.min(bytes.length, 2000);
        for (let i = 1; i < n; i += 2) if (bytes[i] === 0) z++;
        return z > n * 0.4 ? 1 : p * 0.4;
    }
    return 0.5 + languageScore(latin1(bytes, 4000));
}

export async function advancedCandidates(bytes, ctx = {}) {
    const C = [];
    const add = (ops, why, prior) => C.push({ ops: Array.isArray(ops) ? ops : [ops], why, prior });
    add.last = () => C[C.length - 1];
    const prev = ctx.prevOps || [];
    const last = prev[prev.length - 1];
    const ft = detectFileType(bytes);
    const text = latin1(bytes, 3_000_000);
    const isText = printableRatio(bytes) >= 0.9;
    const userSecrets = ctx.keys && ctx.keys.length ? parseUserKeys(ctx.keys) : [];

    // ---------- containers / binaries ----------
    if (!isText || (ft && ft.final)) {
        carve(bytes, add);
        if (!prev.includes("Strings") && (ft?.final || entropy(bytes) < 6.5) && bytes.length > 64) {
            // strings inside PE / OLE / LNK: .NET user strings and macros hold encoded payloads
            add([op("Strings", ["16-bit littleendian", 24, "All printable chars (U)", false, false, false]), op("Remove null bytes", [])], `Pull 16-bit (UTF-16) strings out of ${ft ? "the " + ft.name : "binary data"}: .NET/LNK/Office files keep script payloads there`, ft ? 9 : 4);
            add(op("Strings", ["Single byte", 24, "All printable chars (A)", false, false, false]), `Pull ASCII strings out of ${ft ? "the " + ft.name : "binary data"}`, ft ? 8 : 3);
        }
        if (text.includes("#@~^")) add([op("Microsoft Script Decoder", [])], "Found the '#@~^' marker of a Microsoft Script Encoder (VBE/JSE) block", 18);
        // keys used by the script that produced this binary (XOR / AES / RC4 / DES)
        const scriptText = [ctx.parentText, ctx.rootText].filter(Boolean).join("\n");
        if (userSecrets.length && !ft) {
            for (const c of await userBinaryCandidates(bytes, userSecrets)) C_strong(add, c.ops, c.why, c.prior);
            for (const c of scriptKeyCandidates(bytes, scriptText, userSecrets)) C_strong(add, c.ops, c.why, Math.max(c.prior, 30));
        } else if (scriptText && !ft) {
            xorHints(scriptText, add);
            for (const c of scriptKeyCandidates(bytes, scriptText)) C_strong(add, c.ops, c.why, c.prior);
        }
        // config blobs that carry their own RC4 key (REvil, Remcos, generic)
        if (!ft) for (const c of embeddedKeyCandidates(bytes)) C_strong(add, c.ops, c.why, c.prior);
        return C;
    }

    // ---------- text ----------
    if (userSecrets.length) for (const c of userTextCandidates(text, userSecrets)) if (!c.ops.some(o => prev.includes(o.op))) C_strong(add, c.ops, c.why, c.prior);
    if (text.includes("#@~^") && last !== "Microsoft Script Decoder") add(op("Microsoft Script Decoder", []), "Found the '#@~^' marker of a Microsoft Script Encoder (VBE/JSE) block", 20);

    // .NET RAT settings encrypted with AES-256 + PBKDF2 (AsyncRAT / Quasar / DcRAT)
    if (!prev.includes("Subsection") && /[A-Za-z0-9+/]{64,}/.test(text)) for (const c of await pbkdf2ConfigCandidates(text)) C_strong(add, c.ops, c.why, c.prior);

    // byte / char-code arrays: [Byte[]](31,139,8,...), @(91,118,...), new byte[]{-12, 34,...}, Chr(72) & Chr(105)
    const arrays = text.match(/(?:-?\d{1,3}\s*,\s*){15,}-?\d{1,3}/g) || [];
    if (arrays.length && !/^[\d\s,;-]+$/.test(text.trim())) {
        const signed = arrays.some(a => /-\d/.test(a));
        const total = arrays.reduce((a, s) => a + s.length, 0);
        add([reList("(?:-?\\d{1,3}\\s*,\\s*){15,}-?\\d{1,3}"), fr("[^\\d-]+", ","), op("From Decimal", ["Comma", signed])],
            `Script contains ${arrays.length} array(s) of ${signed ? "signed " : ""}byte values (${total} chars), e.g. [Byte[]](31,139,…)${signed ? " — negative values are Java/.NET signed bytes" : ""}`, 16);
    }

    // Base64 with a junk token inserted (e.g. "@<!" sprinkled through the blob)
    junkTokens(text, add, bytes);
    fillerToken(text, add);

    // several separate blobs: decode them all in place, keeping the surrounding script readable
    const b64blobs = [...new Set([
        ...(text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []),
        // shorter Base64 strings count when they are quoted string literals in code
        ...[...text.matchAll(/["']([A-Za-z0-9+/]{16,}={0,2})["']/g)].map(m => m[1]).filter(b => b.length % 4 === 0 && /[0-9+/=]|[a-z][A-Z]/.test(b)),
    ])].filter(b => /[0-9+/]|[a-z][A-Z][a-z]/.test(b) && !/^[0-9a-f]+$/i.test(b));
    const minBlob = Math.max(16, Math.min(40, ...b64blobs.map(b => b.replace(/=+$/, "").length)));
    if (b64blobs.length >= 2) {
        add([op("Subsection", [`[A-Za-z0-9+/]{${minBlob},}={0,2}`, true, true, true]), op("From Base64", [B64, true, false]), op("Merge", [true])],
            `${b64blobs.length} separate Base64 blobs: decode each one in place (Subsection) so the surrounding code stays readable`, 13);
        // one payload split across several strings / registry values: join every piece, then decode
        add([reList(`[A-Za-z0-9+/=]{${Math.min(30, minBlob)},}`), op("From Base64", [B64, true, false])], `${b64blobs.length} Base64 pieces: join them all and decode as one payload (payload split across strings or registry values)`, 12);
        // the blobs individually (the longest is tried by the basic detector already)
        const byLen = [...new Set(b64blobs)].sort((a, b) => b.length - a.length).slice(1, 3);
        for (const b of byLen) add([reList(escRe(b.slice(0, 24)) + "[A-Za-z0-9+/]*={0,2}"), op("From Base64", [B64, true, false])], `Decode another Base64 blob (${b.length} chars) on its own`, 9);
    }
    const hexblobs = text.match(/(?:[0-9a-fA-F]{2}){20,}/g) || [];
    if (hexblobs.length >= 2) add([op("Subsection", ["(?:[0-9a-fA-F]{2}){20,}", true, true, true]), op("From Hex", ["Auto"]), op("Merge", [true])], `${hexblobs.length} hex strings: decode each one in place`, 11);
    if ((text.match(/(?:\\x[0-9a-f]{2}){4,}/gi) || []).length >= 2) add([op("Subsection", ["(?:\\\\x[0-9a-fA-F]{2})+", false, true, true]), op("From Hex", ["\\x"]), op("Merge", [true])], "\\xNN escaped strings in code: decode each in place", 12);

    // Base64 with characters swapped out (e.g. '%'→'A', '×'→'T')
    substitutedBase64(utf8Text(bytes, text), add);

    // custom Base64 alphabets: known variants + 64-char alphabets defined in the script itself
    customAlphabets(text, ctx, add);

    // reversed Base64 / hex: the reversed text decodes far better than the original
    if (last !== "Reverse") {
        const ns = text.replace(/\s+/g, "");
        const r = [...ns].reverse().join("");
        let dec = null, decR = null, what = "";
        if (ns.length >= 16 && /^[0-9a-fA-F]+$/.test(ns) && ns.length % 2 === 0) { dec = Buffer.from(ns, "hex"); decR = Buffer.from(r, "hex"); what = "hex"; }
        else if (ns.length >= 16 && /^[A-Za-z0-9+/]+={0,2}$|^={0,2}[A-Za-z0-9+/]+$/.test(ns)) { dec = Buffer.from(ns, "base64"); decR = Buffer.from(r, "base64"); what = "Base64"; }
        if (dec && quick(new Uint8Array(decR.subarray(0, 6000))) > quick(new Uint8Array(dec.subarray(0, 6000))) + 0.3) add(op("Reverse", ["Character"]), `This ${what} only decodes to something readable when reversed`, 18);
    }

    // reversed AND rotated (e.g. Morse → Reverse → ROT13)
    if (last !== "Reverse" && last !== "ROT13") {
        const s = text.slice(0, 4000);
        const letters = (s.match(/[A-Za-z]/g) || []).length;
        if (letters > 10) {
            const base = languageScore(s);
            const r = [...s].reverse().join("");
            let best = { k: 0, sc: base };
            for (let k = 1; k < 26; k++) { const sc = languageScore(rot(r, k)); if (sc > best.sc) best = { k, sc }; }
            if (best.k && best.sc > base + 0.2) add([op("Reverse", ["Character"]), op("ROT13", [true, true, false, best.k])], `Text reads correctly after reversing and shifting letters by ${best.k}`, 14);
        }
    }

    // noise characters sprinkled through a command (DOSfuscation / Invoke-Obfuscation), possibly reversed
    noiseChars(text, add, last);

    return C;
}

// ---------------------------------------------------------------------------------------------

/** XOR keys written in the script that decodes the blob: -bxor 35, ^ 0x5A, Xor &H23, xor(…, 'key') */
function xorHints(script, add) {
    const keys = new Map();
    const put = (bytes, src) => { const k = Buffer.from(bytes).toString("hex"); if (bytes.length && !keys.has(k)) keys.set(k, src); };
    for (const m of script.matchAll(/-bxor\s*\(?\s*(0x[0-9a-f]{1,2}|\d{1,3})\b/gi)) put([Number(m[1]) & 255], m[0]);
    for (const m of script.matchAll(/\^\s*(0x[0-9a-f]{1,2}|\d{1,3})\s*[);\]]/gi)) put([Number(m[1]) & 255], m[0]);
    for (const m of script.matchAll(/\bxor\s*\(?\s*(&h[0-9a-f]{1,2}|\d{1,3})\b/gi)) put([m[1].toLowerCase().startsWith("&h") ? parseInt(m[1].slice(2), 16) : Number(m[1])], m[0]);
    for (const m of script.matchAll(/xor[\w]*\s*\(\s*[^,()]{1,40},\s*["']([^"']{2,64})["']/gi)) put([...Buffer.from(m[1], "utf8")], m[0]);
    for (const [hex, src] of [...keys.entries()].slice(0, 4)) {
        C_strong(add, op("XOR", [{ option: "Hex", string: hex.match(/../g).join(" ") }, "Standard", false]), `The script itself XORs with this key (\`${src.trim().slice(0, 40)}\`)`, 18);
    }
}

/** Candidates backed by hard evidence (a key taken from the script that decrypts cleanly). */
function C_strong(add, ops, why, prior) {
    add(ops, why, prior);
    add.last && (add.last().strong = true);
}

function rot(s, k) {
    return s.replace(/[a-z]/gi, c => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + k) % 26) + b); });
}

function carve(bytes, add) {
    const sigs = [
        { hex: [0x1f, 0x8b, 0x08], name: "gzip", then: op("Gunzip", []) },
        { hex: [0x4d, 0x5a], name: "PE (MZ)", then: null, check: (b, i) => { const off = b[i + 0x3c] | (b[i + 0x3d] << 8); return off > 0 && off < 1024 && b[i + off] === 0x50 && b[i + off + 1] === 0x45; } },
        { hex: [0x50, 0x4b, 0x03, 0x04], name: "ZIP", then: null },
        { hex: [0x25, 0x50, 0x44, 0x46, 0x2d], name: "PDF", then: null },
    ];
    const n = Math.min(bytes.length, 8 * 1024 * 1024);
    const found = [];
    for (const s of sigs) {
        for (let i = 1; i < n - s.hex.length && found.length < 6; i++) {
            if (bytes[i] !== s.hex[0]) continue;
            let ok = true;
            for (let j = 1; j < s.hex.length; j++) if (bytes[i + j] !== s.hex[j]) { ok = false; break; }
            if (ok && (!s.check || s.check(bytes, i))) {
                if (s.name === "gzip") { try { zlib.gunzipSync(bytes.subarray(i), { maxOutputLength: 64 << 20 }); } catch (e) { if (!/unexpected end|trailing/i.test(e.message)) continue; } }
                found.push({ i, s });
                break;
            }
        }
    }
    for (const { i, s } of found) {
        const ops = [op("Drop bytes", [0, i, false])];
        if (s.then) ops.push(s.then);
        add(ops, `Found an embedded ${s.name} signature at offset ${i} (0x${i.toString(16)}): carve it out`, s.name === "gzip" ? 16 : 12);
    }
}

/**
 * A filler string repeated all over the payload, even one made of Base64 characters
 * (Emotet documents: "=PO32P=PO32O=PO32w…"). Removing it must leave clearly better data.
 */
function fillerToken(text, add) {
    const t = text.slice(0, 200000);
    if (t.length < 200) return;
    let best = null;
    for (let n = 3; n <= 12; n++) {
        const counts = new Map();
        for (let i = 0; i + n <= t.length; i += 1) { const g = t.substr(i, n); counts.set(g, (counts.get(g) || 0) + 1); }
        for (const [g, c] of counts) {
            if (/^\s|\s$/.test(g) || /^(.)\1+$/.test(g)) continue;
            const cover = c * n / t.length;
            if (c >= 20 && cover >= 0.2 && (!best || cover > best.cover || (cover === best.cover && n > best.tok.length))) best = { tok: g, c, cover };
        }
    }
    if (!best) return;
    const rest = t.split(best.tok).join("");
    // only when the filler is what breaks the encoding: the text is not already valid, the rest is
    const strictB64 = x => { const n = x.replace(/\s+/g, ""); return n.length >= 40 && /^[A-Za-z0-9+/]+={0,2}$/.test(n); };
    if (/^[01\s]+$/.test(t) || /^[0-9a-fA-F\s,:]+$/.test(t) || strictB64(t)) return;
    // a real Base64 run mixes upper case, lower case and digits (a run of digits is a char-code list, not Base64)
    const B64RUN = /(?=[A-Za-z0-9+/]{60,})(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{60,}={0,2}/;
    const restB64 = (strictB64(rest.replace(/^[^A-Za-z0-9+/]*(?:-e(?:nc(?:odedcommand)?)?\s+)?/i, "")) && B64RUN.test(rest)) || (B64RUN.test(rest) && !B64RUN.test(t));
    if (!restB64 && languageScore(rest) < languageScore(t) + 0.2) return;
    const esc = best.tok.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    add(fr(esc, ""), `The filler "${best.tok}" makes up ${(best.cover * 100).toFixed(0)} % of the text (${best.c} times): remove it`, 22);
}

/**
 * Base64 with a junk token inserted or substituted for a real character
 * ("@<!" → "A", "☠" → "B", "za67t" → ""): find tokens that keep interrupting long Base64
 * runs, then try removing the token or replacing it with each Base64 character, keeping the
 * option whose decoded output looks best.
 */
function junkTokens(rawText, add, bytes) {
    let text = rawText;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, 2_000_000)); } catch { /* latin1 */ }
    const tokens = new Map();
    // (a) non-Base64 tokens between Base64 runs (linear scan)
    const parts = text.match(/[A-Za-z0-9+/]+|[^A-Za-z0-9+/]+/g) || [];
    for (let i = 0; i < parts.length; i++) {
        if (/^[A-Za-z0-9+/]/.test(parts[i])) continue;
        if ((parts[i - 1] || "").length < 2 && (parts[i + 1] || "").length < 2) continue;
        // separators may wrap a line break ("@<!\r\n@<!") or repeat ("@<!@<!@<!"): use each piece's repeating unit
        for (const piece of parts[i].split(/\s+/).filter(Boolean)) {
            const cps = [...piece];
            let unit = piece;
            for (let p = 1; p <= cps.length / 2; p++) if (cps.length % p === 0 && cps.slice(0, p).join("").repeat(cps.length / p) === piece) { unit = cps.slice(0, p).join(""); break; }
            if ([...unit].length > 6 || /[="'`(),;]/.test(unit) || tokens.has(unit)) continue;
            if (tokens.size > 40) break;
            tokens.set(unit, text.split(unit).length - 1); // counted once per distinct token
        }
    }
    // (b) an alphanumeric token repeated far more often than chance inside one long blob
    const blob = (text.match(/[A-Za-z0-9+/]{400,}={0,2}/g) || []).sort((a, b) => b.length - a.length)[0];
    if (blob) {
        const sample = blob.slice(0, 60000);
        for (const k of [8, 7, 6, 5, 4]) {
            const cnt = new Map();
            for (let i = 0; i + k <= sample.length; i++) { const g = sample.substr(i, k); cnt.set(g, (cnt.get(g) || 0) + 1); }
            const [g, c] = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0] || [];
            if (g && c >= 15 && c * k > sample.length * 0.03 && !/^(.)\1+$/.test(g) && !/^A+$/.test(g)) { tokens.set(g, c); break; }
        }
    }
    const ranked = [...tokens.entries()].filter(([, c]) => c >= 3).sort((a, b) => b[1] - a[1]).slice(0, 3);
    for (const [tok, count] of ranked) {
        // a blob that still contains the token, to test replacements on
        const testBlob = (text.match(new RegExp(`(?:[A-Za-z0-9+/\\s]|${escRe(tok)}){80,}`, "g")) || []).sort((a, b) => b.length - a.length)[0];
        if (!testBlob) continue;
        let best = null;
        const blobSample = testBlob.slice(0, 200000);
        for (const rep of ["", ...B64CHARS]) {
            const cleaned = blobSample.split(tok).join(rep).replace(/[^A-Za-z0-9+/]/g, "");
            const dec = new Uint8Array(Buffer.from(cleaned.slice(0, cleaned.length - (cleaned.length % 4)), "base64"));
            // a wrong replacement corrupts a few bytes per occurrence; the right one leaves the output clean
            const ft = detectFileType(dec);
            // count bytes typical of text/code; padding NULs are neutral. A wrong replacement turns
            // some bytes into rare symbols / high-bit characters, the right one keeps them ordinary.
            let good = 0, n = 0;
            for (const b of dec) {
                if (b === 0) continue;
                n++;
                if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 32 || b === 10 || b === 13 || b === 9 || "-_./\\:\"'$=(){}[],;&|@#%*+<>?!~".includes(String.fromCharCode(b))) good++;
            }
            const q = ft ? 2 : n ? good / n : 0;
            if (!best || q > best.q) best = { q, rep };
        }
        if (!best || best.q < 0.9) continue;
        add([fr(tok, best.rep, "Simple string")], best.rep
            ? `"${tok}" appears ${count} times inside Base64 data in place of the character '${best.rep}': substitute it back`
            : `The junk token "${tok}" is inserted ${count} times inside Base64 data: remove it`, 16);
    }
}

function utf8Text(bytes, fallback) {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, 3_000_000)); } catch { return fallback; }
}

function substitutedBase64(text, add) {
    const s = text.trim();
    if (s.length < 64 || s.length > 300_000) return;
    const counts = new Map();
    for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
    const foreign = [...counts.keys()].filter(c => !B64CHARS.includes(c) && c !== "=" && !/\s/.test(c));
    const inAlpha = [...counts.entries()].filter(([c]) => B64CHARS.includes(c)).reduce((a, [, n]) => a + n, 0);
    if (!foreign.length || foreign.length > 4 || inAlpha / s.replace(/\s/g, "").length < 0.5) return;
    const missing = [...B64CHARS].filter(c => !counts.has(c));
    if (missing.length < foreign.length || missing.length > foreign.length + 3) return;
    // try every assignment of foreign chars -> missing alphabet chars (tiny search), in normal and reversed order
    const perms = permutations(missing, foreign.length).slice(0, 400);
    let best = null;
    for (const reversed of [false, true]) {
        const base = (reversed ? [...s].reverse().join("") : s).replace(/\s/g, "");
        for (const p of perms) {
            let t = base.slice(0, 2400);
            foreign.forEach((f, i) => { t = t.split(f).join(p[i]); });
            const dec = Buffer.from(t.slice(0, 2400).replace(/=+$/, ""), "base64");
            const q = quick(new Uint8Array(dec));
            if (!best || q > best.q) best = { q, p, reversed };
        }
    }
    if (!best || best.q < 1) return;
    const ops = [];
    if (best.reversed) ops.push(op("Reverse", ["Character"]));
    foreign.forEach((f, i) => ops.push(fr(f, best.p[i], "Simple string")));
    ops.push(op("From Base64", [B64, true, false]));
    add(ops, `Base64 with substituted characters: ${foreign.map((f, i) => `'${f}'→'${best.p[i]}'`).join(", ")}${best.reversed ? " (after reversing the text)" : ""}`, 17);
}

function permutations(arr, k) {
    const out = [];
    const rec = (cur, used) => {
        if (out.length > 2000) return;
        if (cur.length === k) { out.push([...cur]); return; }
        for (let i = 0; i < arr.length; i++) if (!used[i]) { used[i] = true; cur.push(arr[i]); rec(cur, used); cur.pop(); used[i] = false; }
    };
    rec([], []);
    return out;
}

const KNOWN_ALPHABETS = ["A-Za-z0-9-_", "A-Za-z0-9+\\-=", "./0-9A-Za-z=", "A-Za-z0-9_.", "A-Za-z0-9._-", "0-9a-zA-Z+/=", "0-9A-Za-z+/=", "N-ZA-Mn-za-m0-9+/=", "./0-9A-Za-z", "+\\-0-9A-Za-z"];

function expandAlphabet(a) {
    return a.replace(/(.)-(.)/g, (m, x, y) => { let s = ""; for (let c = x.charCodeAt(0); c <= y.charCodeAt(0); c++) s += String.fromCharCode(c); return s; }).replace(/\\-/g, "-");
}

function customAlphabets(text, ctx, add) {
    const s = text.trim();
    if (s.length < 16) return;
    const blob = (s.match(/[A-Za-z0-9+/=._\-]{40,}/g) || []).sort((a, b) => b.length - a.length)[0];
    if (!blob) return;
    // 1) alphabets defined in the script itself (64/65 unique characters in one string)
    const scriptText = (ctx.rootText || "") + "\n" + text;
    const defs = new Set((scriptText.match(/["'`]([!-~]{64,65})["'`]/g) || []).map(q => q.slice(1, -1)).filter(a => new Set(a).size === a.length && /[A-Z]/.test(a) && /[a-z]/.test(a) && /\d/.test(a)));
    for (const a of defs) {
        if (a === B64CHARS || a === B64CHARS + "=") continue;
        const dec = decodeCustom(blob, a);
        if (dec && quick(dec) >= 1) {
            add([op("From Base64", [a, true, false])], `The script defines its own Base64 alphabet "${a.slice(0, 20)}…" and the blob decodes with it`, 18);
        }
    }
    // 2) CyberChef's built-in alternative alphabets, when standard Base64 output is junk
    const std = Buffer.from(blob.replace(/[^A-Za-z0-9+/]/g, "").slice(0, 6000), "base64");
    if (quick(new Uint8Array(std)) >= 1) return;
    for (const a of KNOWN_ALPHABETS) {
        const dec = decodeCustom(blob, expandAlphabet(a));
        if (dec && quick(dec) >= 1.05) add([op("From Base64", [a, true, false])], `Decodes with the alternative Base64 alphabet "${a}"`, 12);
    }
}

function decodeCustom(blob, alphabet) {
    const alpha = alphabet.replace(/=$/, "").slice(0, 64);
    if (alpha.length !== 64) return null;
    const map = new Map([...alpha].map((c, i) => [c, i]));
    const src = [...blob.slice(0, 8000)].filter(c => map.has(c));
    const out = [];
    for (let i = 0; i + 1 < src.length; i += 4) {
        const a = map.get(src[i]), b = map.get(src[i + 1]), c = map.get(src[i + 2]), d = map.get(src[i + 3]);
        out.push((a << 2) | (b >> 4));
        if (c !== undefined) out.push(((b & 15) << 4) | (c >> 2));
        if (d !== undefined) out.push(((c & 3) << 6) | d);
    }
    return new Uint8Array(out.map(x => x & 255));
}

function noiseChars(text, add, last) {
    const s = text.slice(0, 20000);
    if (s.length < 30 || last === "Find / Replace") return;
    // characters that are typical DOSfuscation / Invoke-Obfuscation noise
    const NOISE = ["^", "`", "\"", "+", "'", "~", "|", "\\", "_", "-", "/"];
    const present = NOISE.filter(c => (s.split(c).length - 1) > s.length / 60);
    if (!present.length) return;
    const base = languageScore(s), baseRev = languageScore([...s].reverse().join(""));
    let best = null;
    // try removing subsets of the noisy characters (largest first), with and without reversing
    const subsets = [];
    for (let mask = 1; mask < (1 << present.length) && subsets.length < 64; mask++) subsets.push(present.filter((_, i) => mask & (1 << i)));
    for (const sub of subsets) {
        const cleaned = s.split("").filter(c => !sub.includes(c)).join("");
        for (const rev of [false, true]) {
            const t = rev ? [...cleaned].reverse().join("") : cleaned;
            const sc = languageScore(t);
            if (!best || sc > best.sc) best = { sc, sub, rev };
        }
    }
    if (!best || best.sc < Math.max(base, baseRev) + 0.12) return;
    const cls = "[" + best.sub.map(c => "\\" + c).join("") + "]";
    const ops = [fr(cls, "")];
    if (best.rev) ops.push(op("Reverse", ["Character"]));
    add(ops, `Noise characters ${best.sub.map(c => `'${c}'`).join(" ")} are sprinkled through the text${best.rev ? " and the command is reversed" : ""} (DOSfuscation / Invoke-Obfuscation)`, 13);
}

