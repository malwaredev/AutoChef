/**
 * Candidate generation: look at the current data and propose CyberChef
 * operations (with arguments) that could be the next step of the recipe.
 * Each candidate carries a human-readable reason and a prior (how likely it is).
 */
import { pluginCandidates } from "./plugins.mjs";
import { latin1, printableRatio, detectFileType, languageScore, entropy, looksEncoded as looksEncodedText } from "./analyze.mjs";
import { proposeXorKeys } from "./xor.mjs";
import { advancedCandidates } from "./advanced.mjs";
import zlib from "node:zlib";

/** Pre-check with Node's zlib so CyberChef is only asked to inflate data that really is Deflate
 *  (CyberChef's inflater can spin for a long time on random bytes). */
function inflatesCleanly(bytes, kind) {
    try {
        const opts = { maxOutputLength: 256 * 1024 * 1024 };
        const out = kind === "raw" ? zlib.inflateRawSync(bytes, opts) : kind === "zlib" ? zlib.inflateSync(bytes, opts) : zlib.gunzipSync(bytes, opts);
        return out.length > 0;
    } catch {
        return false;
    }
}

const B64 = "A-Za-z0-9+/=";
const B64URL = "A-Za-z0-9-_";
const op = (name, args) => ({ op: name, args });
const re = (regex, fmt = "List matches") => op("Regular expression", ["User defined", regex, true, true, false, false, false, false, fmt]);

/**
 * @param {Uint8Array} bytes
 * @param {object} ctx { prevOps: string[], crib?: string }
 * @returns {{ops:object[], why:string, prior:number}[]}
 */
export async function generateCandidates(bytes, ctx = {}) {
    const all = [...basicCandidates(bytes, ctx), ...(await advancedCandidates(bytes, ctx)), ...pluginCandidates(bytes, ctx)];
    const seen = new Set();
    return all.filter(c => { const k = JSON.stringify(c.ops); if (seen.has(k)) return false; seen.add(k); return true; });
}

const xorOp = k => op("XOR", [{ option: "Hex", string: k.key }, k.scheme || "Standard", !!k.nullPreserving]);

function basicCandidates(bytes, ctx = {}) {
    const C = [];
    const add = (ops, why, prior) => C.push({ ops: Array.isArray(ops) ? ops : [ops], why, prior });
    const prev = ctx.prevOps || [];
    const last = prev[prev.length - 1];

    const ft = detectFileType(bytes);
    if (ft && ft.final) return C; // already a real file: stop here

    // ---------- compressed containers ----------
    if (ft) {
        if (ft.ext === "gz") add(op("Gunzip", []), "Data starts with 1F 8B: the Gzip signature", 20);
        if (ft.ext === "bz2") add(op("Bzip2 Decompress", [false]), "Data starts with 'BZh': the Bzip2 signature", 20);
        if (ft.ext === "zlib" && inflatesCleanly(bytes, "zlib")) add(op("Zlib Inflate", [0, 0, "Adaptive", false, false]), "Data starts with a Zlib header (78 xx)", 20);
        if (ft.ext === "lzma") add(op("LZMA Decompress", []), "Data starts with 5D 00 00: an LZMA header", 15);
        if (ft.ext === "lz4") add(op("LZ4 Decompress", []), "Data starts with the LZ4 frame magic 04 22 4D 18", 18);
    }

    const pr = printableRatio(bytes);
    const isText = pr >= 0.9;

    // ---------- binary data ----------
    if (!isText) {
        // UTF-16 text (e.g. PowerShell -EncodedCommand payloads)
        const n = Math.min(bytes.length, 2000);
        let zOdd = 0, zEven = 0;
        for (let i = 0; i < n; i++) if (bytes[i] === 0) (i % 2 ? zOdd++ : zEven++);
        if (zOdd > n * 0.35 && zEven < n * 0.05) add(op("Decode text", ["UTF-16LE (1200)"]), "Every second byte is 00: this is UTF-16LE text (typical of PowerShell -EncodedCommand)", 22);
        if (zOdd + zEven > n * 0.3) add(op("Remove null bytes", []), "Lots of 00 bytes between characters: UTF-16 text mixed with single-byte separators; dropping the nulls makes it readable", 10);
        else if (zEven > n * 0.35 && zOdd < n * 0.05) add(op("Decode text", ["UTF-16BE (1201)"]), "Every first byte is 00: this is UTF-16BE text", 18);

        if (!ft) {
            const e = entropy(bytes);
            const hi = Math.min(6.5, 0.8 * Math.log2(Math.max(2, Math.min(bytes.length, 65536)))); // small buffers can't reach 8 bits/byte
            if (e > hi && last !== "Raw Inflate" && inflatesCleanly(bytes, "raw")) add(op("Raw Inflate", [0, 0, "Adaptive", false, false]), "High-entropy binary without a header: could be raw Deflate (e.g. PowerShell DeflateStream)", 8);
            if (last !== "XOR") {
                for (const k of proposeXorKeys(bytes, ctx)) add(xorOp(k), k.why, k.prior);
            }
        }
        return C;
    }

    // ---------- text data ----------
    const text = latin1(bytes, 2_000_000);
    const s = text.trim();
    const ns = s.replace(/\s+/g, "");

    // JWT
    if (/^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*$/.test(ns)) add(op("JWT Decode", []), "Three base64url parts starting with 'eyJ': a JSON Web Token", 25);

    // Base64 (whole input)
    if (ns.length >= 8 && /^[A-Za-z0-9+/]+={0,2}$/.test(ns) && ns.length % 4 !== 1) {
        const strong = /[+/=]$|[0-9]/.test(ns) || ns.length % 4 === 0;
        add(op("From Base64", [B64, true, false]), `Input is made only of Base64 characters${ns.endsWith("=") ? " and ends with '=' padding" : ""}`, strong ? 16 : 8);
    }
    if (ns.length >= 8 && /^[A-Za-z0-9_-]+={0,2}$/.test(ns) && /[-_]/.test(ns)) add(op("From Base64", [B64URL, true, false]), "Input uses the URL-safe Base64 alphabet ('-' and '_')", 14);

    // Base32
    if (ns.length >= 8 && /^[A-Z2-7]+=*$/.test(ns) && (ns.length % 8 === 0 || /=$/.test(ns))) add(op("From Base32", ["A-Z2-7=", true]), "Only uppercase A-Z and digits 2-7 with Base32 length/padding", 15);

    // Hex variants
    if (/^(?:0x)?[0-9a-f]+$/i.test(ns) && ns.replace(/^0x/i, "").length % 2 === 0 && ns.length >= 4) add(op("From Hex", ["Auto"]), "Input is only hexadecimal characters (0-9, A-F) of even length", 17);
    else if (/^([0-9a-f]{2}[\s:,;-]+)+[0-9a-f]{2}$/i.test(s)) add(op("From Hex", ["Auto"]), "Delimited hexadecimal byte values", 17);
    else if (/^((\\x|0x|%)[0-9a-f]{2}[\s,]*)+$/i.test(s)) add(op("From Hex", ["Auto"]), "Escaped hex bytes (\\x41 / 0x41 / %41)", 17);
    if (/^[0-9a-f]{8}[: ]{1,2}([0-9a-f]{2} ){4,}/im.test(s)) add(op("From Hexdump", []), "Looks like a hexdump (offset + hex bytes)", 18);

    // Binary / octal / decimal
    if (/^[01]+$/.test(ns) && ns.length % 8 === 0 && ns.length >= 8) add(op("From Binary", [/\s/.test(s) ? "Space" : "None", 8]), "Only 0s and 1s in groups of 8 bits", 18);
    if (/^([0-7]{3}[\s,]+)+[0-7]{3}$/.test(s) && /[89]/.test(s) === false && !/^[01\s]+$/.test(s)) add(op("From Octal", [s.includes(",") ? "Comma" : "Space"]), "Groups of three octal digits (0-7)", 12);
    if (/^\d{1,3}([\s,;]+\d{1,3}){2,}$/.test(s)) {
        const delim = s.includes(",") ? "Comma" : s.includes(";") ? "Semi-colon" : /\n/.test(s) ? "Line feed" : "Space";
        const nums = s.split(/[\s,;]+/).map(Number);
        if (nums.every(n => n < 256)) add(op("From Decimal", [delim, false]), "A list of decimal numbers 0-255: character codes", 16);
    }

    // character-code obfuscation inside scripts ([char]72, chr(72), String.fromCharCode(72,...))
    if (/(\[char\]\s*\d{2,3}|chrw?\(\s*\d{2,3}|fromcharcode\(\s*\d{2,3})/i.test(text)) {
        add([re("(?:\\[char\\]|chrw?\\(|fromcharcode\\(|,)\\s*(\\d{1,3})", "List capture groups"), op("From Decimal", ["Line feed", false])],
            "Script builds strings from character codes ([char]NN / Chr(NN) / String.fromCharCode)", 14);
    }

    // URL / HTML / unicode / string escapes
    const pct = (text.match(/%[0-9a-f]{2}/gi) || []).length;
    if (pct >= 3) add(op("URL Decode", [true]), `${pct} percent-encoded sequences (%XX)`, pct > text.length / 8 ? 16 : 10);
    if (/%u[0-9a-f]{4}/i.test(text)) add(op("Unescape Unicode Characters", ["%u"]), "%uXXXX unicode escapes (common in JS shellcode loaders)", 14);
    if ((text.match(/\\u[0-9a-f]{4}/gi) || []).length >= 2) add(op("Unescape Unicode Characters", ["\\u"]), "\\uXXXX unicode escapes", 14);
    if ((text.match(/\\x[0-9a-f]{2}|\\[0-7]{3}|\\[nrt]/gi) || []).length >= 3 && !/^((\\x)[0-9a-f]{2})+$/i.test(ns)) add(op("Unescape string", []), "Backslash escape sequences (\\x41, \\n, \\101)", 12);
    if ((text.match(/&(#x?[0-9a-f]+|[a-z]{2,6});/gi) || []).length >= 2) add(op("From HTML Entity", []), "HTML entities (&#65; / &lt;)", 14);
    if ((text.match(/=[0-9A-F]{2}/g) || []).length >= 3 && /=\r?\n|=[0-9A-F]{2}/.test(text) && !/^[A-Za-z0-9+/]+=*$/.test(ns)) add(op("From Quoted Printable", []), "Quoted-printable encoding (=XX)", 8);

    // Morse
    if (/^[.\-\/\s]+$/.test(s) && s.includes(".") && s.includes("-")) add(op("From Morse Code", ["Space", s.includes("/") ? "Forward slash" : "Line feed"]), "Only dots, dashes and separators: Morse code", 15);

    // Base58 / Base85 / Base62 (weaker signals)
    if (ns.length >= 10 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(ns) && !/^[0-9a-f]+$/i.test(ns)) add(op("From Base58", ["123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", true]), "Characters fit the Base58 alphabet (no 0, O, I, l)", 3);
    if (/^<~[\s\S]*~>$/.test(s)) add(op("From Base85", ["!-u", true, "z"]), "Wrapped in <~ ~>: Ascii85", 20);
    else if (ns.length >= 10 && /^[!-u]+$/.test(ns) && /[!-/:-@\[-`]/.test(ns) && (ns.match(/[!-/:-@\[-`]/g) || []).length > ns.length * 0.1) add(op("From Base85", ["!-u", true, "z"]), "Dense mix of letters and punctuation in the Base85 range", 6);

    // ---------- embedded blobs inside larger text (scripts, macros, logs) ----------
    const isWhole = /^[A-Za-z0-9+/]+={0,2}$/.test(ns) || /^[0-9a-f]+$/i.test(ns);
    if (!isWhole) {
        const b64runs = text.match(/[A-Za-z0-9+/]{24,}={0,2}/g) || [];
        const longest = b64runs.sort((a, b) => b.length - a.length)[0];
        if (longest && longest.length >= 24 && /[0-9+/]/.test(longest)) {
            // shortest quantifier that still selects only the longest blob (large quantifiers are slow in CyberChef's regex engine)
            const second = (b64runs[1] || "").replace(/=+$/, "").length;
            const L = Math.min(longest.replace(/=+$/, "").length, Math.max(24, second + 1, Math.min(100, longest.length)));
            const isHexOnly = /^[0-9a-f]+$/i.test(longest);
            if (!isHexOnly) add([re(`[A-Za-z0-9+/]{${L},}={0,2}`), op("From Base64", [B64, true, false])],
                `Found an embedded Base64 blob (${longest.length} chars) inside the text${/-e(nc|ncodedcommand)?\s/i.test(text) ? " after a PowerShell -EncodedCommand switch" : /frombase64string/i.test(text) ? " passed to FromBase64String()" : ""}`, 15);
        }
        const hexruns = text.match(/(?:[0-9a-fA-F]{2}){16,}/g) || [];
        const lh = hexruns.sort((a, b) => b.length - a.length)[0];
        if (lh) add([re(`(?:[0-9a-fA-F]{2}){${Math.min(lh.length / 2, 2000)},}`), op("From Hex", ["Auto"])], `Found an embedded hex string (${lh.length} chars)`, 12);
    }

    // ---------- script de-obfuscation (PowerShell / cmd / JS) ----------
    if ((text.match(/['"]\s*\+\s*['"]/g) || []).length >= 2) add(op("Find / Replace", [{ option: "Regex", string: "['\"]\\s*\\+\\s*['\"]" }, "", true, false, true, false]), "Strings split and re-joined with '+' (string concatenation obfuscation)", 10);
    if ((text.match(/`[a-zA-Z]/g) || []).length >= 3) add(op("Find / Replace", [{ option: "Regex", string: "`(?=[a-zA-Z])" }, "", true, false, true, false]), "PowerShell backtick obfuscation (I`E`X)", 10);
    if ((text.match(/\^[a-zA-Z]/g) || []).length >= 4 && /cmd|\/c/i.test(text)) add(op("Find / Replace", [{ option: "Regex", string: "\\^(?=.)" }, "", true, false, true, false]), "cmd.exe caret obfuscation (p^o^w^e^r^s^h^e^l^l)", 10);

    // ---------- reversed / rotated text ----------
    if (last !== "Reverse") {
        const rev = [...s.slice(0, 5000)].reverse().join("");
        const revNs = rev.replace(/\s+/g, "");
        const reversedB64 = /^=+[A-Za-z0-9+/]/.test(ns) && /^[A-Za-z0-9+/=]+$/.test(ns);
        const reversedWords = languageScore(rev) > languageScore(s) + 0.15;
        const reversedIoc = /ptth|exe\.|llehsrewop|lld\./i.test(s);
        if (reversedB64 || reversedWords || reversedIoc) add(op("Reverse", ["Character"]), reversedB64 ? "Starts with '=' padding: Base64 that has been reversed" : reversedIoc ? "Contains reversed keywords like 'ptth' / 'exe.'" : "Text reads better backwards", reversedB64 ? 18 : 14);
        void revNs;
    }

    const letters = (s.match(/[A-Za-z]/g) || []).length;
    if (letters > 8 && letters / Math.max(1, s.length) > 0.5 && last !== "ROT13") {
        const base = languageScore(s);
        let best = { k: 0, sc: base };
        for (let k = 1; k < 26; k++) {
            const sc = languageScore(rot(s.slice(0, 3000), k));
            if (sc > best.sc) best = { k, sc };
        }
        if (best.k && (best.sc > base + 0.12 || (best.sc > base + 0.06 && best.sc > 0.35))) add(op("ROT13", [true, true, false, best.k]), `Caesar/ROT brute force: shifting letters by ${best.k} gives readable text`, 13);
        const at = languageScore(atbash(s.slice(0, 3000)));
        if (at > base + 0.15 && at > best.sc) add(op("Atbash Cipher", []), "Atbash (A↔Z) substitution gives readable text", 10);
    }
    if (last !== "ROT47" && s.length > 8) {
        const base = languageScore(s);
        const r = rot47(s.slice(0, 3000));
        if (languageScore(r) > base + 0.15) add(op("ROT47", [47]), "ROT47 (rotates all printable ASCII) gives readable text", 12);
    }

    // printable but gibberish & high entropy: maybe XOR'ed into printable range
    // (e.g. a zero-filled PE XOR'ed with a printable key looks like "s3cr3ts3cr3t...")
    if (languageScore(s) < 0.3 && last !== "XOR") {
        // known-plaintext (crib) hits are precise; brute-force guesses only when nothing better is on offer
        const weakOk = !C.some(c => c.prior >= 12) && !looksEncodedText(s);
        for (const k of proposeXorKeys(bytes, ctx)) if (k.prior >= 10 || weakOk) add(xorOp(k), k.why, C.length ? k.prior - 2 : k.prior);
    }

    return C;
}

function rot(s, k) {
    return s.replace(/[a-z]/gi, c => {
        const b = c <= "Z" ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - b + k) % 26) + b);
    });
}
function atbash(s) {
    return s.replace(/[a-z]/gi, c => {
        const b = c <= "Z" ? 65 : 97;
        return String.fromCharCode(25 - (c.charCodeAt(0) - b) + b);
    });
}
function rot47(s) {
    return s.replace(/[!-~]/g, c => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)));
}
