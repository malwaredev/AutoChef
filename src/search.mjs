/**
 * The recipe search. Starting from the input, AutoChef repeatedly:
 *   1. looks at the current data and proposes candidate CyberChef operations,
 *   2. runs each one with the real CyberChef engine,
 *   3. scores the outputs, and keeps the most promising ones (beam search).
 * The best end states become ranked recipe suggestions.
 */
import { tryRunOps, magicRecipes } from "./chef.mjs";
import { scoreOutput, toText, hexOf, guessLanguage, iocCount, binaryStrings, isUtf16Text } from "./analyze.mjs";
import { generateCandidates } from "./candidates.mjs";
import { prettyRecipe, cyberChefUrl } from "./recipe.mjs";
import { libraryCandidates, matchLibrary, teamCandidates } from "./library.mjs";
import { encryptedAssessment } from "./crypto.mjs";
import { fastSolve } from "./fastpath.mjs";
import { extractFindings, summarizeFindings } from "./findings.mjs";
import { extractOffice, isOle, isZip } from "./office.mjs";
import { readableView } from "./cleanup.mjs";
import { analyzePE, isPE } from "./pe.mjs";
import { identifyRansom, ransomMessage } from "./ransom.mjs";
import { loadPlugins } from "./plugins.mjs";

const DEFAULTS = {
    maxDepth: 64,
    beamWidth: 8,
    maxCandidatesPerNode: 18,
    maxResults: 5,
    timeBudgetMs: 12000,
    useMagic: true,
    useLibrary: true,
    keys: [],
    crib: "",
};

/**
 * Script text used to look for keys: huge encoded blobs are collapsed so that keys/IVs written
 * after a multi-megabyte payload are still seen.
 */
function condense(bytes) {
    const t = Buffer.from(bytes.subarray(0, 8_000_000)).toString("latin1").replace(/[A-Za-z0-9+/=]{2000,}/g, m => m.slice(0, 64) + "…");
    return t.slice(0, 500000);
}

function layerWhy(id, i) {
    const what = {
        "From Base64": "valid Base64", "From Base64 (URL-safe)": "URL-safe Base64", "From Base32": "Base32 (A-Z, 2-7)", "From Base58": "Base58", "From Base62": "Base62",
        "From Base45": "Base45", "From Base85": "Base85 / Ascii85", "From Hex": "hexadecimal", "From Binary": "binary (0/1 groups of 8)", "From Octal": "octal numbers",
        "From Decimal": "decimal byte values", "URL Decode": "URL (percent) encoding", "From HTML Entity": "HTML entities", "Unescape Unicode Characters": "\\u escapes",
        "From Quoted Printable": "quoted-printable", "LZString Decompress": "LZString-compressed Base64", Gunzip: "gzip data (1F 8B)", "Zlib Inflate": "zlib data (78 xx)", "Raw Inflate": "raw Deflate data",
        Reverse: "reversed text", ROT47: "ROT47-rotated text", "Atbash Cipher": "Atbash-substituted text",
    }[id] || id;
    if (/^Code-point offset/.test(id)) return `Layer ${i + 1}: every character is one byte shifted by ${id.replace("Code-point offset ", "")} (all characters fall in one 256-code-point block, e.g. CJK); subtracting it gives the next layer`;
    return `Layer ${i + 1}: ${/^ROT13 \(shift/.test(id) ? "letters rotated (" + id.replace("ROT13 ", "") + ")" : /^XOR/.test(id) ? "single-byte " + id : what}; decoding it gives the next recognisable layer`;
}

function hashBytes(b) {
    let h = 0x811c9dc5;
    const step = b.length > 1_000_000 ? Math.floor(b.length / 500_000) : 1;
    for (let i = 0; i < b.length; i += step) { h ^= b[i]; h = Math.imul(h, 0x01000193); }
    return `${b.length}:${(h >>> 0).toString(16)}`;
}

/** How promising is a state to keep expanding (not the same as how "final" it looks). */
function potential(state) {
    const k = state.info.kind;
    let p = state.score;
    if (k === "encoded-text") p += 40;
    if (k === "compressed") p += 45;
    if (k === "binary") p += 15;
    if (state.info.obfuscation) p += 30;
    p += (state.lastPrior || 0);
    p -= state.steps.length * 1.5;
    return p;
}

async function magicSeeds(bytes, crib) {
    if (bytes.length > 256 * 1024) return [];
    return magicRecipes(bytes, { depth: 3, intensive: false, crib: "" }, 3000);
}

/**
 * @param {Uint8Array} input
 * @param {Partial<typeof DEFAULTS>} options
 */
export async function autoChef(input, options = {}) {
    await loadPlugins();
    // Office documents: pull the macros out first (CyberChef has no operation for this), then search on the macro source
    if (isOle(input) || isZip(input)) {
        let office = null;
        try { office = await extractOffice(input); } catch (e) { office = null; }
        if (office && office.text.trim()) {
            const text = Buffer.from(office.text, "utf8");
            const per = Math.max(3000, Math.floor((options.timeBudgetMs || DEFAULTS.timeBudgetMs) / (1 + office.payloads.length)));
            const res = await searchCore(new Uint8Array(text), { ...options, timeBudgetMs: per });
            for (const r of res.results) r.inputBase64 = text.toString("base64"); // recipes apply to the extracted text
            // strings stored in document streams (form fields, document text) are searched on their own
            for (const p of office.payloads) {
                const r2 = await searchCore(new Uint8Array(Buffer.from(p.text, "utf8")), { ...options, timeBudgetMs: per });
                for (const r of r2.results) r.inputBase64 = Buffer.from(p.text, "utf8").toString("base64");
                for (const r of r2.results) r.steps.unshift({ ops: ["AutoChef: string from " + p.where], why: `Long string stored in the document stream ${p.where} (recipes below start from this string)` });
                res.results.push(...r2.results);
                for (const a of r2.alerts) if (!res.alerts.some(x => x.type === a.type && x.value === a.value)) res.alerts.push(a);
            }
            res.results.sort((a, b) => b.score - a.score);
            res.results = res.results.slice(0, (options.maxResults || DEFAULTS.maxResults) + 2);
            const F = extractFindings(office.text);
            const extracted = {
                score: 0, confidence: "high", summary: `Extracted ${office.modules.length} VBA module(s)${office.embedded.length ? ` and ${office.embedded.length} link(s)/macro sheet(s)` : ""} from the ${office.container}`,
                recipe: [], recipeString: "", cyberChefUrl: "", preprocessing: true,
                steps: [{ ops: ["AutoChef: Office macro extraction"], why: "Parsed the document's compound file / zip (MS-CFB, MS-OVBA) and decompressed the VBA source. CyberChef has no operation for this, so the recipes below start from this extracted text." }],
                loop: null, newIocs: F.length, library: null,
                output: { size: text.length, isText: true, preview: office.text.slice(0, 8000), hexPreview: null, base64: text.toString("base64"), fileType: null, language: "VBA", entropy: null, iocs: null, strings: null, findings: F },
            };
            const seen = new Set(res.alerts.map(a => a.type + "|" + a.value));
            for (const f of F) if (!seen.has(f.type + "|" + f.value)) res.alerts.push({ ...f, result: 0 });
            res.alertSummary = summarizeFindings(res.alerts);
            return { ...res, office: { container: office.container, modules: office.modules, embedded: office.embedded, streams: office.streams.length }, results: [extracted, ...res.results] };
        }
    }
    return searchCore(input, options);
}

async function searchCore(input, options = {}) {
    const opt = { ...DEFAULTS, ...Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined && v !== null)) };
    const t0 = Date.now();
    let budget = opt.timeBudgetMs;
    const timeUp = () => Date.now() - t0 > budget;

    const s0 = scoreOutput(input);
    const start = { bytes: input, steps: [], score: s0.score, info: s0.info, lastPrior: 0 };
    const seen = new Map([[hashBytes(input), start]]);
    const all = [];
    let tried = 0, failed = 0;

    const expand = async (state, cand, timeoutMs) => {
        tried++;
        const r = await tryRunOps(state.bytes, cand.ops, timeoutMs);
        if (!r.ok) { failed++; return null; }
        const out = r.bytes;
        if (!out.length || out.length > 64 * 1024 * 1024) return null;
        const h = hashBytes(out);
        if (seen.has(h)) {
            // the fast path reached an output another candidate already produced: keep its evidence
            const ex = seen.get(h);
            if (cand.strong && ex && ex.steps.length) { ex.steps[ex.steps.length - 1].strong = true; if (cand.fpScore) ex.fpScore = Math.max(ex.fpScore || 0, cand.fpScore); }
            return null;
        }
        const sc = scoreOutput(out);
        const child = {
            bytes: out,
            steps: [...state.steps, ...(cand.layers
                ? cand.layers.map(l => ({ ops: l.ops, why: l.why, source: "AutoChef fast path", strong: !l.weak }))
                : [{ ops: cand.ops, why: cand.why, source: cand.source || "AutoChef", library: cand.library, strong: !!cand.strong }])],
            score: sc.score,
            info: sc.info,
            lastPrior: cand.prior || 0,
            fpScore: cand.fpScore || 0,
            parentKey: state.key || "root",
            // the most recent readable script on this path (keys for XOR/AES/RC4 are usually written there)
            ctxText: state.info.kind === "text" || state.info.kind === "encoded-text" ? condense(state.bytes) : state.ctxText,
            key: h,
        };
        seen.set(h, child);
        all.push(child);
        return child;
    };

    let frontier = [start];
    const rootText = condense(input);

    // Seed with CyberChef's own Magic suggestions (as a baseline the search can extend)
    if (opt.useMagic) {
        for (const ops of await magicSeeds(input, opt.crib)) {
            const c = await expand(start, { ops, why: "Suggested by CyberChef's built-in Magic operation", prior: 5, source: "CyberChef Magic" });
            if (c) frontier.push(c);
        }
    }

    if (process.env.AC_TRACE) console.error(Date.now() - t0, "ms after Magic");
    // Known patterns from the recipe library (published analyses) are tried first
    const libMatches = opt.useLibrary ? matchLibrary(rootText) : [];
    for (const cand of opt.useLibrary ? [...libraryCandidates(rootText), ...teamCandidates(rootText)] : []) {
        const c = await expand(start, cand, 30000);
        if (c) frontier.push(c);
    }

    if (process.env.AC_TRACE) console.error(Date.now() - t0, "ms after library");
    // Fast path: native search over layered encodings, verified by CyberChef
    const fastCands = (bytes, ms) => fastSolve(bytes, { timeMs: ms }).map(sol => ({
        ops: sol.ops, prior: sol.score >= 0.4 ? 30 : 14, strong: sol.score >= 0.4, fpScore: sol.score, // weak fast-path guesses are only candidates
        why: `Layered encoding solved: ${sol.steps.map(x => x.id).join(" → ")}`,
        layers: sol.steps.map((x, i) => ({ ops: x.ops, why: layerWhy(x.id, i), weak: sol.score < 0.4 })),
    }));
    for (const cand of fastCands(input, Math.min(4000, opt.timeBudgetMs / 3))) {
        const c = await expand(start, cand, 30000);
        if (c) frontier.push(c);
    }
    if (process.env.AC_TRACE) console.error(Date.now() - t0, "ms after fast path");
    // the fast path already produced clean, readable text (verified by CyberChef): look for alternatives briefly, then stop
    if (frontier.some(c => c.fpScore >= 0.55 && c.info.kind === "text" && c.score >= 55 && !c.info.obfuscation && !/[A-Za-z0-9+\/]{40,}|-bxor|\bxor\b/i.test(Buffer.from(c.bytes.subarray(0, 200000)).toString("latin1")) && !(opt.keys || []).length)) budget = Math.min(budget, Date.now() - t0 + 3000);

    // depth 0 always runs, so a slow machine still gets the first round of candidates
    for (let depth = 0; depth < opt.maxDepth && frontier.length && (depth === 0 || !timeUp()); depth++) {
        const children = [];
        for (const state of frontier) {
            const late = timeUp() && !(depth === 0 && state === start);
            if (late) break;
            const prevOps = state.steps.flatMap(s => s.ops.map(o => o.op));
            const extra = state.steps.length && state.steps.length <= 2 && !state.steps.some(x => x.source === "AutoChef fast path") ? fastCands(state.bytes, 250) : [];
            const cands = [...extra, ...(await generateCandidates(state.bytes, { prevOps, crib: opt.crib, rootText, parentText: state.ctxText, keys: opt.keys }))]
                .sort((a, b) => b.prior - a.prior)
                .slice(0, opt.maxCandidatesPerNode);
            // candidates run in parallel across the CyberChef worker pool
            // block ciphers on large data are slow in pure-JS CyberChef: give them more time
            const slow = cand => cand.ops.some(o => /Decrypt$|^ChaCha$|^Salsa20$|^XSalsa20$|^Rabbit$|^RC4/.test(o.op)) ? Math.max(20000, Math.ceil(state.bytes.length / 10000) * 1000) : undefined;
            const outs = await Promise.all(cands.map(async cand => { if (timeUp() && !(depth === 0 && state === start)) return null; const tc = Date.now(); const r = await expand(state, cand, slow(cand)); if (process.env.AC_TRACE && Date.now() - tc > 1000) console.error("slow candidate", Date.now() - tc, "ms", cand.ops.map(o => o.op).join("+")); return r; }));
            for (const c of outs) if (c) children.push(c);
        }
        children.sort((a, b) => potential(b) - potential(a));
        // beam = best children overall + the most plausible child of each parent
        // (so one noisy parent can't crowd out a strong, specific signal elsewhere)
        const keep = new Set(children.slice(0, opt.beamWidth));
        const bestPerParent = new Map();
        for (const c of children) {
            const k = c.parentKey;
            const v = (c.lastPrior || 0) * 2 + c.score;
            if (!bestPerParent.has(k) || v > bestPerParent.get(k).v) bestPerParent.set(k, { c, v });
        }
        for (const { c } of bestPerParent.values()) keep.add(c);
        frontier = [...keep];
        if (process.env.AC_TRACE) console.error(Date.now() - t0, "ms depth", depth, "children", children.length, "frontier", frontier.map(f => f.steps.map(s => s.ops.map(o => o.op).join("+")).join(" > ") + " [" + f.score.toFixed(1) + "/" + f.info.kind + "]"));
    }

    // ---------- rank results ----------
    if (process.env.AC_TRACE_ALL) for (const s of all) console.error("ALL", s.score.toFixed(1), s.info.kind, s.steps.map(x => x.ops.map(o => o.op).join("+")).join(" > "), JSON.stringify(Buffer.from(s.bytes.subarray(0, 60)).toString("latin1")));
    // IOCs that only appear after decoding are the strongest evidence a recipe is right
    const inputText = rootText;
    const newIocs = s => {
        const i = s.info.iocs;
        if (!i) return 0;
        return [...i.urls, ...i.ips, ...i.domains].filter(x => !inputText.includes(x)).length;
    };
    // Bacon / A1Z26 / Morse give bare capitals by design (no case, often no spaces): judge them by the fast path, not by the text scorer
    const LOSSY = /^(Bacon Cipher Decode|A1Z26 Cipher Decode|From Morse Code)$/;
    const lossyEnd = s => s.fpScore >= 0.45 && LOSSY.test(s.steps.at(-1)?.ops.at(-1)?.op || "");
    const afterLossy = s => { const ops = s.steps.flatMap(st => st.ops.map(o => o.op)); const i = ops.findIndex(o => LOSSY.test(o)); return i >= 0 && i < ops.length - 1; };
    // text that still carries a long encoded blob is an intermediate step, whatever the fast path thought
    const blobLeft = s => s.info.kind === "text" && /[A-Za-z0-9+\/]{60,}={0,2}/.test(Buffer.from(s.bytes.subarray(0, 300000)).toString("latin1"));
    const byUserKey = s => s.steps.some(st => /your key/.test(st.why || "")) && s.info.kind !== "binary";
    const ranked = all
        .filter(s => !start.info.script || byUserKey(s) || s.info.kind === "file" || newIocs(s) > 0 || s.score > start.score + 15) // natural non-Latin input: only clear wins
        .filter(s => byUserKey(s) || lossyEnd(s) || (s.fpScore >= 0.45 && s.info.kind === "text") || s.info.kind !== "encoded-text" && s.info.kind !== "compressed" && (s.score > start.score + 5 || (newIocs(s) > 0 && s.score >= 25)
            // readable text with the input's obfuscation gone (short commands score low on language alone)
            || (start.info.obfuscation && !s.info.obfuscation && s.info.kind === "text" && s.score >= 20)))
        // random-looking binary with no strings, IOCs or file signature is an intermediate, not an answer
        .filter(s => !(s.info.kind === "binary" && !s.info.fileType && !newIocs(s) && s.info.entropy > 6.8))
        .map(s => { s.newIocs = newIocs(s); if (lossyEnd(s)) return { s, rank: 30 + 100 * (s.fpScore - 0.45) - 4 * Math.log2(1 + s.steps.length) }; return { s, rank: s.score + (cpOffset(s) ? 20 : 0) + 8 * Math.min(3, s.newIocs) - 4 * Math.log2(1 + s.steps.length) + (s.steps.some(st => st.library) ? 4 : 0) + ((s.steps.some(st => st.strong && st.source !== "AutoChef fast path") || (s.steps.some(st => st.strong) && !blobLeft(s))) && s.info.kind !== "binary" && s.bytes.length >= 32 ? 12 : 0) + (blobLeft(s) || s.steps.some(st => st.strong && st.source !== "AutoChef fast path") ? 0 : 15 * (s.fpScore || 0)) - txPenalty(s) + (byUserKey(s) ? (k => k === 0 ? 30 : -10 * k)(s.steps.length - 1 - s.steps.map(st => /your key/.test(st.why || "")).lastIndexOf(true)) : 0)
            // a few bytes of "text" carved out of a large input are rarely the answer
            - (s.bytes.length < 48 && input.length > 400 ? 20 : 0) }; })
        .sort((a, b) => b.rank - a.rank)
        .map(x => { if (process.env.AC_RANK) console.error("RANK", x.rank.toFixed(1), x.s.score.toFixed(1), (x.s.fpScore || 0).toFixed(2), x.s.steps.map(st => st.ops.map(o => o.op).join("+")).join(" > ")); return x; })
        .filter((x, i, arr) => !(arr[0].s.score >= 80 && x.s.score < 50 && !x.s.newIocs)) // hide weak noise when a strong answer exists
        .slice(0, opt.maxResults)
        .map(({ s }) => s);

    // express repeated layers as a CyberChef loop (Label … Jump), verified to give identical output
    const results = [];
    for (const s of ranked) results.push(await withReadable(formatResult(s, input, await loopify(s, input)), s.bytes));

    // Honest verdict when the data is encrypted and no key was found in the sample
    let assessment = null;
    const strongResult = results.some(r => r.confidence !== "low");
    if (!strongResult) {
        let where = null, ea = encryptedAssessment(input);
        if (ea) where = "the input";
        else {
            for (const st of all.filter(x => x.info.kind === "binary").sort((a, b) => a.steps.length - b.steps.length)) {
                const a2 = encryptedAssessment(st.bytes);
                if (a2 && st.steps.length <= 2) { ea = a2; where = `the data after ${st.steps.flatMap(x => x.ops.map(o => o.op)).join(" → ")}`; break; }
            }
        }
        if (ea) assessment = {
            encrypted: true, where, entropy: ea.entropy,
            message: `${where[0].toUpperCase() + where.slice(1)} looks encrypted (${ea.entropy} bits/byte, evenly distributed byte values) and no key that decrypts it was found in the sample. ` +
                "It can't be decrypted without the key. If this is a file encrypted by ransomware, the per-file key is normally protected with the attackers' public key (RSA or elliptic-curve), so only their private key, a leaked master key, or a flaw in that specific family (see nomoreransom.org) can recover it. " +
                "If you have the key (for example from a memory dump or the dropper script), type it in the Keys field (CLI: --key) or paste the script together with the data.",
        };
    }
    const hash = identifyHash(rootText);
    // a readable text input (a note, a script) is not "encrypted data", whatever a derived blob looks like
    if (assessment && start.info.kind === "text" && !encryptedAssessment(input)) assessment = null;

    // alerts: every finding across the suggested outputs, once, most serious first
    const seenF = new Set(), alerts = [];
    for (const [i, r] of results.entries()) for (const f of r.output.findings || []) {
        const k = f.type + "|" + f.value;
        if (seenF.has(k)) continue;
        seenF.add(k); alerts.push({ ...f, result: i + 1 });
    }
    const LV = { high: 0, medium: 1, info: 2 };
    alerts.sort((a, b) => LV[a.level] - LV[b.level]);
    // ransom note? (the input itself, or a decoded output)
    let ransom = identifyRansom(Buffer.from(input.subarray(0, 300000)).toString(isUtf16Text(input) ? "utf16le" : "utf8"), opt.fileName || "");
    for (const r of results) if (!ransom && r.output.isText) ransom = identifyRansom(r.output.preview || "", "");
    if (ransom) ransom.message = ransomMessage(ransom);
    return {
        assessment,
        hash,
        ransom,
        inputPE: isPE(input) ? safePE(input) : null,
        alerts,
        alertSummary: summarizeFindings(alerts),
        input: { size: input.length, score: +start.score.toFixed(1), info: slimInfo(start.info) },
        libraryMatches: libMatches.map(e => ({ id: e.id, name: e.name, family: e.family, source: e.source })),
        results,
        stats: { tried, failed, explored: all.length, ms: Date.now() - t0, timedOut: timeUp() },
    };
}

/** Run a user-edited recipe and score it (used by the editor's "Re-bake"). */
export async function bakeAndScore(input, ops) {
    const r = await tryRunOps(input, ops);
    if (r.ok) {
        const sc = scoreOutput(r.bytes);
        return { ok: true, ...(await withReadable(formatResult({ bytes: r.bytes, steps: [{ ops, why: "Your recipe" }], score: sc.score, info: sc.info }, input), r.bytes)) };
    }
    {
        // find the step that fails so the editor can point at it
        let failedStep = typeof r.failedStep === "number" ? r.failedStep : null;
        for (let i = 1; i <= ops.length && failedStep === null; i++) if (!(await tryRunOps(input, ops.slice(0, i))).ok) failedStep = i - 1;
        return { ok: false, error: r.error, failedStep };
    }
}

/**
 * One-way hashes look like hex/Base64 but carry no message: say so instead of "decoding" them.
 * Lengths and prefixes follow hashcat's example hashes (https://hashcat.net/wiki/doku.php?id=example_hashes).
 */
export function identifyHash(text) {
    const t = text.trim();
    if (t.length > 200 || /\s/.test(t)) return null;
    const HEX = { 32: ["MD5", "NTLM", "MD4"], 40: ["SHA-1", "RIPEMD-160"], 56: ["SHA-224", "SHA3-224"], 64: ["SHA-256", "SHA3-256", "BLAKE2s-256"], 96: ["SHA-384", "SHA3-384"], 128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"] };
    let types = null;
    if (/^[0-9a-f]+$/i.test(t) && HEX[t.length] && (/^[0-9a-f]+$/.test(t) || /^[0-9A-F]+$/.test(t))) types = HEX[t.length];
    else if (/^\$2[abxy]?\$\d{2}\$[.\/A-Za-z0-9]{53}$/.test(t)) types = ["bcrypt"];
    else if (/^\$6\$[^$]{1,16}\$[.\/A-Za-z0-9]{86}$/.test(t)) types = ["sha512crypt (Linux /etc/shadow)"];
    else if (/^\$5\$[^$]{1,16}\$[.\/A-Za-z0-9]{43}$/.test(t)) types = ["sha256crypt"];
    else if (/^\$1\$[^$]{1,8}\$[.\/A-Za-z0-9]{22}$/.test(t)) types = ["md5crypt"];
    else if (/^\$argon2(id|i|d)\$/.test(t)) types = ["Argon2"];
    else if (/^\$y\$/.test(t)) types = ["yescrypt"];
    if (!types) return null;
    return {
        types,
        message: `This looks like a ${types.join(" / ")} hash. A hash is a one-way fingerprint, not an encoding or encryption: there is nothing to decode and no key that reverses it. ` +
            "The original value can only be found by guessing candidates and comparing hashes (for example hashcat or John the Ripper with a wordlist), or by looking the hash up in a database of known hashes. CyberChef's \"Analyse hash\" operation shows the possible algorithms.",
    };
}

/** decoded by the code-point offset layer (every character = one byte + a fixed offset): structurally near-certain once CyberChef reproduces it */
const cpOffset = s => /every character is one byte shifted by/.test(s.steps[0]?.why || "") && s.info.kind !== "encoded-text";

/** Chains of several letter/byte transforms (ROT, XOR, Vigenère …) can bend almost anything into English-looking noise */
const TX_OPS = /^(ROT13|ROT47|ROT8000|XOR|ADD|SUB|Vigenère Decode|Atbash Cipher|Affine Cipher Decode|Rail Fence Cipher Decode|Reverse)$/;
function txPenalty(s) {
    if (s.fpScore >= 0.45) return 0;
    const n = s.steps.flatMap(st => st.ops).filter(o => TX_OPS.test(o.op)).length;
    return n >= 2 ? 6 * (n - 1) : 0;
}

/** Collapse long runs of identical explanation steps for display. */
function compactSteps(steps) {
    const out = [];
    for (const st of steps) {
        const item = { ops: st.ops.map(o => o.op), why: st.why, source: st.source, library: st.library };
        const prev = out[out.length - 1], prev2 = out[out.length - 2];
        if (prev && prev.why === item.why && prev.ops.join() === item.ops.join()) { prev.times = (prev.times || 1) + 1; continue; }
        if (prev2 && prev2.why === item.why && prev2.ops.join() === item.ops.join() && prev.times && prev.times === prev2.times) { prev2.times++; continue; }
        out.push(item);
    }
    return out;
}

function slimInfo(info) {
    const { iocs, ...rest } = info;
    return rest;
}

function confidence(score, s = {}) {
    let level = score >= 80 ? 2 : score >= 60 ? 1 : 0;
    // indicators that only appear after decoding, or a match with a published recipe, raise confidence
    if (s.newIocs) level = Math.max(level, 1);
    if (s.steps && s.steps.some(st => st.library) && (s.newIocs || score >= 50)) level = 2;
    // three or more ROT/XOR/Reverse-style transforms without fast-path confirmation: possible, never certain
    if (s.steps && !(s.fpScore >= 0.45) && s.steps.flatMap(st => st.ops).filter(o => TX_OPS.test(o.op)).length >= 3) level = 0;
    return ["low", "medium", "high"][level];
}

function summarize(info) {
    if (info.kind === "file") return `Decoded to a ${info.fileType}`;
    if (info.kind === "binary") {
        const n = info.iocs ? iocCount(info.iocs) : 0;
        return n ? `Decoded to binary data (e.g. shellcode) whose strings contain ${[info.iocs.urls.length && `${info.iocs.urls.length} URL(s)`, info.iocs.ips.length && `${info.iocs.ips.length} IP(s)`, info.iocs.domains.length && `${info.iocs.domains.length} domain(s)`].filter(Boolean).join(", ") || n + " indicator(s)"}` : "Decoded to binary data";
    }
    const bits = [];
    if (info.language) bits.push(`${info.language} code`);
    else bits.push("readable text");
    const n = info.iocs ? iocCount(info.iocs) : 0;
    if (n) {
        const parts = [];
        if (info.iocs.urls.length) parts.push(`${info.iocs.urls.length} URL(s)`);
        if (info.iocs.ips.length) parts.push(`${info.iocs.ips.length} IP(s)`);
        if (info.iocs.domains.length) parts.push(`${info.iocs.domains.length} domain(s)`);
        if (info.iocs.files.length) parts.push(`${info.iocs.files.length} file name(s)`);
        if (parts.length) bits.push(`containing ${parts.join(", ")}`);
    }
    return "Decoded to " + bits.join(" ");
}

/**
 * Find the longest block of steps repeated 3+ times back-to-back and rewrite it as
 * Label → block → Jump (CyberChef's loop construct). Kept only if CyberChef produces
 * byte-identical output with the loop.
 */
async function loopify(s, input) {
    // ignore blob-length quantifiers ({1234,}) when comparing steps: they differ per layer
    const keys = s.steps.map(st => JSON.stringify(st.ops).replace(/\{\d+,\}/g, "{N,}"));
    let best = null;
    for (let k = 1; k <= 4; k++) {
        for (let i = 0; i + 3 * k <= keys.length; i++) {
            let r = 1;
            while (i + (r + 1) * k <= keys.length && keys.slice(i + r * k, i + (r + 1) * k).join() === keys.slice(i, i + k).join()) r++;
            if (r >= 3 && (!best || k * (r - 1) > best.k * (best.r - 1))) best = { i, k, r };
        }
    }
    if (!best) return null;
    const flat = st => st.flatMap(x => x.ops);
    const label = "autochef_loop";
    // block with the smallest quantifier seen across repetitions, so the regex matches in every layer
    const reps = Array.from({ length: best.r }, (_, r) => flat(s.steps.slice(best.i + r * best.k, best.i + (r + 1) * best.k)));
    const block = reps[0].map((o, j) => {
        if (o.op !== "Regular expression") return o;
        const qs = reps.map(rep => Number((String(rep[j].args[1]).match(/\{(\d+),\}/) || [])[1])).filter(Number.isFinite);
        if (!qs.length) return o;
        const args = [...o.args];
        args[1] = String(args[1]).replace(/\{\d+,\}/, `{${Math.min(...qs)},}`);
        return { op: o.op, args };
    });
    const ops = [
        ...flat(s.steps.slice(0, best.i)),
        { op: "Label", args: [label] },
        ...block,
        { op: "Jump", args: [label, best.r - 1] },
        ...flat(s.steps.slice(best.i + best.k * best.r)),
    ];
    const check = await tryRunOps(input, ops, 30000);
    if (!check.ok || Buffer.compare(Buffer.from(check.bytes), Buffer.from(s.bytes)) !== 0) return null;
    return { ops, note: `Steps ${best.i + 1}–${best.i + best.k} repeat ${best.r} times; written as a CyberChef loop (Label/Jump)` };
}

function safePE(b) { try { return analyzePE(b); } catch { return null; } }

/** Add a cleaned-up "readable view" of decoded scripts (display only; not part of the recipe) */
async function withReadable(r, bytes) {
    if (r.output.isText) {
        try { const v = await readableView(toText(bytes, 300000), r.output.language); if (v) r.output.readable = v.slice(0, 200000); } catch { /* keep the plain output */ }
    }
    return r;
}

/** Indicators and artefacts in the output (text, or the printable strings of binary data) */
function findingsOf(s, isText) {
    const text = isText ? toText(s.bytes, 2_000_000) : (s.info.strings ? [].concat(s.info.strings.text || s.info.strings).join("\n") : binaryStrings(s.bytes, 5).text);
    return extractFindings(text || "");
}

function formatResult(s, input, loop) {
    const ops = loop ? loop.ops : s.steps.flatMap(st => st.ops);
    const isText = s.info.kind === "text" || s.info.kind === "encoded-text";
    return {
        score: +s.score.toFixed(1),
        confidence: confidence(s.score, s),
        summary: summarize(s.info),
        recipe: ops,
        recipeString: prettyRecipe(ops),
        cyberChefUrl: cyberChefUrl(ops, input),
        steps: compactSteps(s.steps),
        loop: loop ? loop.note : null,
        newIocs: s.newIocs || 0,
        library: (s.steps.find(st => st.library) || {}).library || null,
        output: {
            size: s.bytes.length,
            isText,
            preview: isText ? toText(s.bytes, 8000) : null,
            hexPreview: isText ? null : hexOf(s.bytes, 0, 512),
            base64: s.bytes.length <= 10 * 1024 * 1024 ? Buffer.from(s.bytes).toString("base64") : null,
            fileType: s.info.fileType || null,
            language: s.info.language || (isText ? guessLanguage(toText(s.bytes, 20000)) : null),
            entropy: s.info.entropy,
            iocs: s.info.iocs || null,
            strings: !isText && s.info.strings ? s.info.strings : null,
            findings: findingsOf(s, isText),
            pe: !isText && isPE(s.bytes) ? safePE(s.bytes) : null,
        },
    };
}
