/**
 * Key recovery for classical ciphers, without a key from the user:
 *   Vigenère (index of coincidence + chi-squared per column), Affine (all 312 keys),
 *   Rail Fence (2–12 rails), repeating-key XOR (Hamming distance + per-column English scoring),
 *   Bacon, A1Z26 and Morse code.
 *
 * Each function mirrors the CyberChef operation it proposes, so the CyberChef recipe reproduces
 * the output exactly. Results are only proposed when they read much better than the input.
 */
const ENG = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074].map(x => x / 100);
import { languageScore } from "./analyze.mjs";
const op = (name, args) => ({ op: name, args });
const lettersOf = s => s.toLowerCase().replace(/[^a-z]/g, "");

function chi2(counts, n) {
    let c = 0;
    for (let i = 0; i < 26; i++) { const e = ENG[i] * n; c += (counts[i] - e) ** 2 / (e || 1); }
    return c;
}

/** CyberChef "Vigenère Decode": the key advances on letters only, case kept */
export function vigenereDecode(s, key) {
    const k = key.toLowerCase();
    let j = 0;
    return s.replace(/[a-z]/gi, c => {
        const o = c <= "Z" ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - o - (k.charCodeAt(j++ % k.length) - 97) + 26) % 26 + o);
    });
}

/** Recover a Vigenère key from ciphertext (needs ~20 letters per key character). */
export function crackVigenere(s, maxLen = 16) {
    const L = lettersOf(s).slice(0, 4000);
    if (L.length < 60) return null;
    const ic = cols => {
        let tot = 0;
        for (const col of cols) {
            const f = new Array(26).fill(0);
            for (const ch of col) f[ch.charCodeAt(0) - 97]++;
            const n = col.length;
            tot += n > 1 ? f.reduce((a, x) => a + x * (x - 1), 0) / (n * (n - 1)) : 0;
        }
        return tot / cols.length;
    };
    const split = k => Array.from({ length: k }, (_, i) => [...L].filter((_, j) => j % k === i).join(""));
    const keyFor = k => split(k).map(col => {
        let bs = Infinity, bshift = 0;
        for (let sh = 0; sh < 26; sh++) {
            const f = new Array(26).fill(0);
            for (const ch of col) f[(ch.charCodeAt(0) - 97 - sh + 26) % 26]++;
            const c = chi2(f, col.length);
            if (c < bs) { bs = c; bshift = sh; }
        }
        return String.fromCharCode(97 + bshift);
    }).join("");
    // smallest key length whose columns look like shifted English (multiples of the true length score as high)
    const ics = [];
    for (let k = 1; k <= Math.min(maxLen, Math.floor(L.length / 8)); k++) ics.push({ k, v: ic(split(k)) });
    const top = Math.max(...ics.map(x => x.v));
    if (top < 0.05) return null;
    const pick = ics.find(x => x.v >= top * 0.88 && x.v >= 0.05);
    let key = keyFor(pick.k);
    for (let p = 1; p < key.length; p++) if (key.length % p === 0 && key === key.slice(0, p).repeat(key.length / p)) { key = key.slice(0, p); break; }
    // short texts: columns have few letters, so refine each key letter by how English the whole decode reads
    if (L.length < 600 && key.length > 1) {
        const sample = s.slice(0, 700);
        const arr = [...key];
        for (let i = 0; i < arr.length; i++) {
            let bs = -1, bc = arr[i];
            for (let c = 0; c < 26; c++) {
                arr[i] = String.fromCharCode(97 + c);
                const v = languageScore(vigenereDecode(sample, arr.join("")));
                if (v > bs) { bs = v; bc = arr[i]; }
            }
            arr[i] = bc;
        }
        key = arr.join("");
    }
    if (/^a+$/.test(key)) return null; // identity: not Vigenère
    return { key, out: vigenereDecode(s, key), ops: [op("Vigenère Decode", [key])], id: `Vigenère Decode (key "${key}", recovered)` };
}

const modInv = (a, m) => { for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x; return null; };
export function affineDecode(s, a, b) {
    const inv = modInv(a, 26);
    return s.replace(/[a-z]/gi, c => {
        const up = c <= "Z", i = c.toLowerCase().charCodeAt(0) - 97;
        const r = String.fromCharCode(97 + ((((i - b) * inv) % 26) + 26) % 26);
        return up ? r.toUpperCase() : r;
    });
}
/** Best Affine key by English letter statistics. a = 1 is a Caesar shift (handled elsewhere). */
export function crackAffine(s) {
    const L = lettersOf(s).slice(0, 3000);
    if (L.length < 30) return null;
    const f0 = new Array(26).fill(0);
    for (const ch of L) f0[ch.charCodeAt(0) - 97]++;
    let best = null;
    for (const a of [3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]) {
        const inv = modInv(a, 26);
        for (let b = 0; b < 26; b++) {
            const f = new Array(26).fill(0);
            for (let i = 0; i < 26; i++) f[((((i - b) * inv) % 26) + 26) % 26] += f0[i];
            const c = chi2(f, L.length);
            if (!best || c < best.c) best = { a, b, c };
        }
    }
    if (!best || best.c > L.length * 0.6) return null;
    if (best.a === 25 && best.b === 25) return { out: affineDecode(s, 25, 25), ops: [op("Atbash Cipher", [])], id: "Atbash Cipher" };
    return { out: affineDecode(s, best.a, best.b), ops: [op("Affine Cipher Decode", [best.a, best.b])], id: `Affine Cipher Decode (a=${best.a}, b=${best.b}, recovered)` };
}

/** CyberChef "Rail Fence Cipher Decode" (offset 0) */
export function railFenceDecode(cipher, key, offset = 0) {
    const cycle = (key - 1) * 2, plain = new Array(cipher.length);
    let j = 0;
    for (let y = 0; y < key; y++) for (let x = 0; x < cipher.length; x++) if ((y + x + offset) % cycle === 0 || (y - x - offset) % cycle === 0) plain[x] = cipher[j++];
    return plain.join("");
}
export function railFenceCandidates(s, score) {
    if (s.length < 12) return [];
    const out = [];
    for (let k = 2; k <= Math.min(12, s.length - 1); k++) {
        const r = railFenceDecode(s, k);
        out.push({ k, out: r, sc: score(r.slice(0, 1500)) });
    }
    out.sort((a, b) => b.sc - a.sc);
    return out.slice(0, 1).map(x => ({ out: x.out, ops: [op("Rail Fence Cipher Decode", [x.k, 0])], id: `Rail Fence Cipher Decode (${x.k} rails)`, sc: x.sc }));
}

/** Repeating-key XOR (Vigenère over bytes): key size by normalised Hamming distance, then per-column English score */
const ham = (a, b) => { let d = 0; for (let i = 0; i < a.length; i++) { let x = a[i] ^ b[i]; while (x) { d += x & 1; x >>= 1; } } return d; };
const FREQ = (() => { const f = new Float64Array(256); const s = " etaoinshrdlcumwfgypbvkjxqz"; for (let i = 0; i < s.length; i++) { f[s.charCodeAt(i)] = 27 - i; if (i) f[s.charCodeAt(i) - 32] = (27 - i) * 0.6; } for (const c of ".,-_/\\:;'\"()=$%0123456789\n\r\t") f[c.charCodeAt(0)] = 4; return f; })();
export function crackRepeatingXor(bytes) {
    const b = bytes.subarray(0, 4096);
    if (b.length < 40) return null;
    const sizes = [];
    for (let k = 2; k <= Math.min(40, Math.floor(b.length / 4)); k++) {
        const blocks = Math.min(8, Math.floor(b.length / k) - 1);
        let d = 0;
        for (let i = 0; i < blocks; i++) d += ham(b.subarray(i * k, i * k + k), b.subarray((i + 1) * k, (i + 2) * k)) / k;
        sizes.push({ k, d: d / blocks });
    }
    sizes.sort((x, y) => x.d - y.d);
    let best = null;
    for (const { k } of sizes.slice(0, 6)) {
        const key = Buffer.alloc(k);
        let total = 0;
        for (let c = 0; c < k; c++) {
            let bs = -1, bk = 0;
            for (let kb = 0; kb < 256; kb++) {
                let sc = 0;
                for (let i = c; i < b.length; i += k) { const p = b[i] ^ kb; sc += (p >= 32 && p < 127) || p === 10 || p === 13 || p === 9 ? FREQ[p] + 1 : -30; }
                if (sc > bs) { bs = sc; bk = kb; }
            }
            key[c] = bk; total += bs;
        }
        // a key made of a shorter repeated unit is that unit
        let kk = key;
        for (let p = 1; p < k; p++) if (k % p === 0 && kk.equals(Buffer.concat(Array(k / p).fill(kk.subarray(0, p))))) { kk = kk.subarray(0, p); break; }
        const dec = Buffer.from(b.map((x, i) => x ^ kk[i % kk.length]));
        let good = 0;
        for (const x of dec) if ((x >= 97 && x <= 122) || x === 32) good++;
        const norm = good / dec.length - 0.004 * kk.length;
        if (!best || norm > best.norm) best = { key: Buffer.from(kk), norm };
    }
    if (!best || best.key.length < 2) return null;
    const out = Buffer.from(bytes.map((x, i) => x ^ best.key[i % best.key.length]));
    const printable = [...best.key].every(x => x >= 32 && x < 127);
    return {
        out, id: `XOR with recovered ${best.key.length}-byte key${printable ? ` "${best.key.toString("latin1")}"` : ""}`,
        ops: [op("XOR", [{ option: "Hex", string: best.key.toString("hex").match(/../g).join(" ") }, "Standard", false])],
    };
}

/**
 * Repeating-key ADD (byte + key[i mod n], mod 256), e.g. Fortra's 16-byte "(byte - key[i % 16]) & 255" layer.
 * Key length from the index of coincidence of each column (addition keeps equal plaintext bytes equal
 * within a column, so text columns repeat far more often than 1/256), then each key byte by letter frequency.
 */
export function crackRepeatingAdd(bytes) {
    const b = bytes.subarray(0, 4096);
    if (b.length < 48) return null;
    const cnt = new Uint32Array(256);
    const ic = k => {
        let same = 0, pairs = 0;
        for (let c = 0; c < k; c++) {
            cnt.fill(0); let n = 0;
            for (let i = c; i < b.length; i += k) { same += 2 * cnt[b[i]]++; n++; } // sum of v*(v-1) built incrementally
            pairs += n * (n - 1);
        }
        return pairs ? same / pairs : 0;
    };
    const maxK = Math.min(40, Math.floor(b.length / 12)); // >= 12 samples per key byte
    if (maxK < 2) return null;
    const whole = ic(1);
    // quick exit for data without periodic structure (random or compressed bytes): sampled key lengths
    let anyHigh = false;
    for (let k = 2; k <= maxK && !anyHigh; k++) if (ic(k) >= Math.max(0.012, whole * 1.6)) anyHigh = true;
    if (!anyHigh) return null;
    const sizes = [];
    for (let k = 2; k <= maxK; k++) sizes.push({ k, v: ic(k) });
    // a multiple of the true key length scores about as well as the length itself: prefer the shortest near the top
    const top = Math.max(...sizes.map(x => x.v));
    if (top < Math.max(0.012, whole * 1.6)) return null; // no periodic structure: not a repeating key
    const lens = sizes.filter(x => x.v >= top * 0.85).map(x => x.k).sort((a, c) => a - c).slice(0, 3);
    // plaintext models: English-like text, or Base64 (flat frequencies, fixed alphabet)
    const B64 = new Uint8Array(256); for (const c of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") B64[c.charCodeAt(0)] = 1;
    const models = [
        p => (p >= 32 && p < 127) || p === 10 || p === 13 || p === 9 ? FREQ[p] + 1 : -30,
        p => B64[p] ? 1 : -30,
    ];
    let best = null;
    for (const k of lens) for (const m of models) {
        const key = Buffer.alloc(k);
        for (let c = 0; c < k; c++) {
            let bs = -Infinity, bk = 0;
            for (let kb = 0; kb < 256; kb++) {
                let sc = 0;
                for (let i = c; i < b.length; i += k) sc += m((b[i] + kb) & 255);
                if (sc > bs) { bs = sc; bk = kb; }
            }
            key[c] = bk;
        }
        // Base64 model: many shifts keep a column inside the alphabet. Base64 decodes 4 characters at a time,
        // so choose each group of 4 key bytes together by how text-like the decoded bytes are.
        if (m === models[1] && k % 4 === 0) refineB64Key(b, key, B64);
        let kk = key;
        for (let p = 1; p < k; p++) if (k % p === 0 && kk.equals(Buffer.concat(Array(k / p).fill(kk.subarray(0, p))))) { kk = kk.subarray(0, p); break; }
        const dec = Buffer.from(b.map((x, i) => (x + kk[i % kk.length]) & 255));
        let good = 0;
        for (const x of dec) if (m === models[1] ? B64[x] : (x >= 32 && x < 127) || x === 10 || x === 13 || x === 9) good++;
        const norm = good / dec.length - 0.002 * kk.length;
        if (!best || norm > best.norm) best = { key: Buffer.from(kk), norm };
    }
    if (!best || best.key.length < 2 || best.norm < 0.9) return null;
    const out = Buffer.from(bytes.map((x, i) => (x + best.key[i % best.key.length]) & 255));
    return {
        out, id: `ADD with recovered ${best.key.length}-byte key`,
        ops: [op("ADD", [{ option: "Hex", string: best.key.toString("hex").match(/../g).join(" ") }])],
    };
}

const B64V = (() => { const v = new Int16Array(256).fill(-1); const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; for (let i = 0; i < 64; i++) v[a.charCodeAt(i)] = i; return v; })();
function refineB64Key(b, key, B64) {
    const k = key.length, rows = Math.floor(b.length / k);
    if (rows < 4) return;
    // per column: every key byte that puts the whole column inside the Base64 alphabet (padding '=' only at the end)
    const opts = [];
    for (let c = 0; c < k; c++) {
        const ok = [];
        for (let kb = 0; kb < 256; kb++) {
            let bad = 0;
            for (let r = 0; r < rows; r++) if (B64V[(b[r * k + c] + kb) & 255] < 0) bad++;
            if (bad === 0) ok.push(kb);
        }
        opts.push(ok.length && ok.length <= 40 ? ok : [key[c]]);
    }
    const byteScore = x => x === 0 ? 0.6 : (x >= 32 && x < 127) || x === 10 || x === 13 || x === 9 ? 1 + FREQ[x] / 27 : -3;
    for (let g = 0; g < k; g += 4) {
        const [o0, o1, o2, o3] = opts.slice(g, g + 4);
        if (o0.length * o1.length * o2.length * o3.length > 400000) continue;
        let best = -Infinity, bk = null;
        for (const k0 of o0) for (const k1 of o1) for (const k2 of o2) for (const k3 of o3) {
            let sc = 0;
            for (let r = 0; r < rows; r++) {
                const i = r * k + g;
                const v0 = B64V[(b[i] + k0) & 255], v1 = B64V[(b[i + 1] + k1) & 255], v2 = B64V[(b[i + 2] + k2) & 255], v3 = B64V[(b[i + 3] + k3) & 255];
                sc += byteScore((v0 << 2 | v1 >> 4) & 255) + byteScore((v1 << 4 | v2 >> 2) & 255) + byteScore((v2 << 6 | v3) & 255);
            }
            if (sc > best) { best = sc; bk = [k0, k1, k2, k3]; }
        }
        if (bk) for (let j = 0; j < 4; j++) key[g + j] = bk[j];
    }
}

// ---------- lossy alphabets ----------
const MORSE = { ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9" };
export const LOSSY_DECODERS = [
    {
        id: "From Morse Code",
        fits: t => /^[.\-\s\/|]+$/.test(t) && /[.]/.test(t) && /-/.test(t) && t.length >= 5,
        run: t => {
            const words = t.trim().split(/\s*[\/|]\s*|\n+/);
            return words.map(w => w.split(/\s+/).map(x => MORSE[x] || "").join("")).join(" ");
        },
        ops: t => [op("From Morse Code", ["Space", /\//.test(t) ? "Forward slash" : "Line feed"])],
    },
    {
        id: "A1Z26 Cipher Decode",
        fits: t => /^\s*\d{1,2}(?:[\s,;:-]+\d{1,2})+\s*$/.test(t) && t.match(/\d+/g).every(n => +n >= 1 && +n <= 26) && t.match(/\d+/g).length >= 4,
        run: t => t.trim().split(/\s+/).map(w => w.split(/[,;:-]/).map(n => String.fromCharCode(96 + +n)).join("")).join(" "),
        // CyberChef splits on one delimiter: put every number on its own, then decode (word gaps are lost)
        ops: t => [...(/[-,;:]/.test(t) ? [op("Find / Replace", [{ option: "Regex", string: "[-,;:\\s]+" }, " ", true, false, true, false])] : []), op("A1Z26 Cipher Decode", ["Space"])],
    },
    {
        id: "Bacon Cipher Decode",
        fits: t => /^[ABab\s]+$/.test(t) && (t.replace(/\s/g, "").length % 5 === 0) && t.replace(/\s/g, "").length >= 15,
        run: t => {
            const bits = t.replace(/[^ABab]/g, "").toUpperCase().replace(/A/g, "0").replace(/B/g, "1");
            const full = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", std = "ABCDEFGHIKLMNOPQRSTUWXYZ";
            const dec = alpha => (bits.match(/.{5}/g) || []).map(c => { const n = parseInt(c, 2); return n < alpha.length ? alpha[n] : "?"; }).join("");
            const codes = (bits.match(/.{5}/g) || []).map(c => parseInt(c, 2));
            return codes.some(n => n >= 24) || codes.some(n => n === 9 || n === 21) ? dec(full) : dec(std);
        },
        ops: t => {
            const bits = t.replace(/[^ABab]/g, "").toUpperCase().replace(/A/g, "0").replace(/B/g, "1");
            const codes = (bits.match(/.{5}/g) || []).map(c => parseInt(c, 2));
            // the 24-letter table has no code above 23: use it only when it fits and the 26-letter one doesn't read better
            const complete = codes.some(n => n >= 24) || codes.filter(n => n === 9 || n === 21).length > 0;
            return [op("Bacon Cipher Decode", [complete ? "Complete" : "Standard (I=J and U=V)", "A/B", false])];
        },
    },
];
