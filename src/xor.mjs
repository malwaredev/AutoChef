/**
 * XOR key recovery. These only *propose* keys; every proposal is then run
 * through CyberChef's own "XOR" operation and scored like any other step.
 */
import { printableRatio, languageScore, latin1, detectFileType, binaryStrings, extractIOCs, iocCount } from "./analyze.mjs";

const toHex = key => [...key].map(b => b.toString(16).padStart(2, "0")).join(" ");

function xorBytes(data, key, max = data.length) {
    const n = Math.min(max, data.length);
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = data[i] ^ key[i % key.length];
    return out;
}

function quickScore(bytes) {
    if (detectFileType(bytes)?.final) return 2;
    const p = printableRatio(bytes);
    if (p < 0.8) {
        // binary output (e.g. shellcode): judge by the strings it contains
        const st = binaryStrings(bytes, 6);
        if (!st.text) return p * 0.5;
        const ioc = iocCount(extractIOCs(st.text)) ? 0.4 : 0;
        return p * 0.3 + st.coverage * 0.5 + languageScore(st.text) * 0.9 + ioc;
    }
    return p * 0.5 + languageScore(latin1(bytes, 4000));
}

/** Known-plaintext cribs typical of malware payloads. */
const CRIBS = [
    { name: "PE header", bytes: [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0] },
    { name: "PDF header", text: "%PDF-1." },
    { name: "ZIP header", bytes: [0x50, 0x4b, 0x03, 0x04] },
    { name: "HTML", text: "<html" },
    { name: "URL", text: "http://" },
    { name: "URL", text: "https://" },
];

function smallestPeriod(ks) {
    for (let p = 1; p <= Math.floor(ks.length / 2); p++) {
        let ok = true;
        for (let i = p; i < ks.length; i++) if (ks[i] !== ks[i - p]) { ok = false; break; }
        if (ok) return ks.slice(0, p);
    }
    return null;
}

function xorScheme(data, k, scheme, nullPreserving) {
    const out = new Uint8Array(data.length);
    let key = k;
    for (let i = 0; i < data.length; i++) {
        const o = data[i];
        const keep = nullPreserving && (o === 0 || o === key);
        const x = keep ? o : o ^ key;
        out[i] = x;
        if (!keep && scheme === "Input differential") key = o;
        if (!keep && scheme === "Output differential") key = x;
    }
    return out;
}

function hamming(a, b) {
    let d = 0;
    for (let i = 0; i < a.length; i++) { let x = a[i] ^ b[i]; while (x) { d += x & 1; x >>= 1; } }
    return d;
}

/**
 * @param {Uint8Array} data
 * @param {{crib?:string}} opts
 * @returns {{key:string, why:string, prior:number}[]}  key as hex string for CyberChef
 */
export function proposeXorKeys(data, opts = {}) {
    const out = [];
    const sample = data.subarray(0, 4096);
    if (sample.length < 4) return out;

    // 1) crib / known plaintext attack (strongest signal)
    const cribs = [...CRIBS];
    if (opts.crib) cribs.unshift({ name: `your crib "${opts.crib}"`, text: opts.crib });
    for (const c of cribs) {
        const cb = c.bytes || [...c.text].map(ch => ch.charCodeAt(0));
        if (cb.length > sample.length) continue;
        // try the crib at offset 0 (headers / leading URLs)
        const ks = cb.map((b, i) => b ^ sample[i]);
        const key = smallestPeriod(ks);
        if (key && key.length <= Math.floor(cb.length / 2) && !key.every(k => k === 0)) {
            const dec = xorBytes(sample, key, 512);
            if (quickScore(dec) > 0.6) out.push({ key: toHex(key), why: `Known-plaintext attack: assuming the data starts with a ${c.name}, the XOR key is hex ${toHex(key)} (${key.length} byte${key.length > 1 ? "s" : ""})`, prior: 12 });
        }
    }

    // 2) single-byte XOR brute force
    const singles = [];
    for (let k = 1; k < 256; k++) singles.push({ k, s: quickScore(xorBytes(sample, [k], 1024)) });
    singles.sort((a, b) => b.s - a.s);
    for (const { k, s } of singles.slice(0, 2)) {
        if (s > 0.75) out.push({ key: toHex([k]), why: `Single-byte XOR brute force: key 0x${k.toString(16).padStart(2, "0")} gives the most readable output of all 255 keys`, prior: 6 });
    }

    // 3) repeating-key XOR (Vigenère-style) using normalised Hamming distance
    // 2b) rolling XOR (key byte changes with position: k, k+1, k+2… or k, k-1…) as a 256-byte repeating key,
    //     differential schemes, and null-preserving XOR (zero bytes and key bytes left untouched)
    {
        let best = null;
        for (const step of [1, 255, 2, 3]) {
            for (let k = 0; k < 256; k++) {
                const key = Array.from({ length: 256 }, (_, i) => (k + i * step) & 255);
                const sc = quickScore(xorBytes(sample, key, 1024));
                if (!best || sc > best.sc) best = { sc, k, step, key };
            }
        }
        if (best && best.sc > 0.9 && best.sc >= (singles[0]?.s ?? 0)) {
            const st = best.step === 255 ? -1 : best.step;
            out.push({ key: toHex(best.key), why: `Rolling XOR: key starts at 0x${best.k.toString(16).padStart(2, "0")} and changes by ${st > 0 ? "+" : ""}${st} every byte (expressed as a 256-byte repeating key)`, prior: 7 });
        }
        for (const scheme of ["Input differential", "Output differential"]) {
            let b2 = null;
            for (let k = 0; k < 256; k++) {
                const sc = quickScore(xorScheme(sample.subarray(0, 1024), k, scheme, false));
                if (!b2 || sc > b2.sc) b2 = { sc, k };
            }
            if (b2.sc > 0.9 && b2.sc > (singles[0]?.s ?? 0) + 0.1) out.push({ key: toHex([b2.k]), scheme, why: `XOR with ${scheme.toLowerCase()} (each byte is XOR'ed with the ${scheme.startsWith("Input") ? "previous input" : "previous output"} byte), initial key 0x${b2.k.toString(16).padStart(2, "0")}`, prior: 6 });
        }
        let b3 = null;
        for (let k = 1; k < 256; k++) {
            const sc = quickScore(xorScheme(sample.subarray(0, 1024), k, "Standard", true));
            if (!b3 || sc > b3.sc) b3 = { sc, k };
        }
        if (b3.sc > 0.9 && b3.sc > (singles[0]?.s ?? 0) + 0.1) out.push({ key: toHex([b3.k]), nullPreserving: true, why: `Null-preserving XOR with key 0x${b3.k.toString(16).padStart(2, "0")} (zero bytes and bytes equal to the key are left as-is, a common malware trick)`, prior: 6 });
    }

    if (sample.length >= 64) {
        const sizes = [];
        for (let ks = 2; ks <= (sample.length >= 1024 ? 128 : sample.length >= 256 ? 64 : 32); ks++) {
            const blocks = Math.min(8, Math.floor(sample.length / ks) - 1);
            if (blocks < 2) break;
            let d = 0;
            for (let b = 0; b < blocks; b++) d += hamming(sample.subarray(b * ks, (b + 1) * ks), sample.subarray((b + 1) * ks, (b + 2) * ks)) / ks;
            sizes.push({ ks, d: d / blocks });
        }
        sizes.sort((a, b) => a.d - b.d);
        for (const { ks } of sizes.slice(0, 3)) {
            // strategy A: per column, choose byte giving most English-like column
            const keyA = [], keyB = [];
            for (let col = 0; col < ks; col++) {
                const colBytes = [];
                for (let i = col; i < sample.length; i += ks) colBytes.push(sample[i]);
                let best = 0, bestK = 0;
                for (let k = 0; k < 256; k++) {
                    let s = 0;
                    for (const b of colBytes) {
                        const c = b ^ k;
                        if (c === 32) s += 3;
                        else if ((c >= 97 && c <= 122)) s += 2;
                        else if ((c >= 65 && c <= 90) || (c >= 48 && c <= 57)) s += 1;
                        else if (c >= 33 && c < 127 || c === 10 || c === 13) s += 0.3;
                        else s -= 3;
                    }
                    if (s > best) { best = s; bestK = k; }
                }
                keyA.push(bestK);
                // strategy B: binary payloads are dominated by 0x00 -> most frequent byte is the key byte
                const f = new Map();
                for (const b of colBytes) f.set(b, (f.get(b) || 0) + 1);
                keyB.push([...f.entries()].sort((a, b) => b[1] - a[1])[0][0]);
            }
            for (const [key, how] of [[keyA, "text-frequency"], [keyB, "null-byte frequency"]]) {
                const reduced = smallestPeriod(key.concat(key)) || key;
                if (reduced.length === 1 && singles[0].k === reduced[0]) continue;
                const dec = xorBytes(sample, reduced, 1024);
                if (quickScore(dec) > 0.7) out.push({ key: toHex(reduced), why: `Repeating-key XOR analysis (${how}): ${reduced.length}-byte key (hex ${toHex(reduced)}) found via Hamming-distance key-length detection`, prior: 5 });
            }
        }
    }

    // de-duplicate
    const seen = new Set();
    return out.filter(o => !seen.has(o.key) && seen.add(o.key));
}
