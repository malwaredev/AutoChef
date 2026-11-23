/**
 * Advanced deep test (1,500+ cases): the kind of strings people use to test a decoder –
 * multi-layer encoding chains, compression, classical ciphers (with no key given), and
 * encryption where the user types the key/password into AutoChef's key field.
 *
 * Plaintexts are real: attacker command lines and test descriptions from Atomic Red Team (MIT).
 * Encoders are in encoders.mjs (Node / lz-string, never CyberChef).
 *
 *   node test/advanced/run-advanced.mjs              all suites
 *   node test/advanced/run-advanced.mjs layers 200   one suite, N cases
 *   SUITE filter: layers | classical | keyed
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TRANSFORMS, CLASSICAL, KEYED } from "./encoders.mjs";
import { autoChef } from "../../src/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const suiteArg = process.argv[2] || "all";
const nArg = Number(process.argv[3]) || null;
let seed = 777;
const rng = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
const rnd = n => Buffer.from(Array.from({ length: n }, () => Math.floor(rng() * 256)));
const pick = a => a[Math.floor(rng() * a.length)];

const art = JSON.parse(fs.readFileSync(path.join(HERE, "..", "corpus", "art-commands.json"), "utf8"));
const ascii = s => /^[\x09\x0a\x0d\x20-\x7e]+$/.test(s);
const commands = art.map(a => a.command.replace(/\r\n/g, "\n")).filter(c => c.length >= 40 && c.length <= 400 && ascii(c));
const prose = art.map(a => a.description).filter(d => d && d.length >= 140 && d.length <= 600 && ascii(d) && /^[A-Z]/.test(d));
const isPrintable = b => b.every(x => (x >= 32 && x < 127) || x === 9 || x === 10 || x === 13);
const norm = s => s.replace(/\s+/g, " ").trim();
const lossyNorm = s => s.toUpperCase().replace(/[^A-Z0-9]/g, "");

const cases = [];
// ---- suite 1: multi-layer chains (2–6 layers)
const N1 = suiteArg === "layers" ? (nArg || 1000) : suiteArg === "all" ? 1000 : 0;
for (let i = 0; i < N1; i++) {
    const plain = pick(rng() < 0.6 ? commands : prose);
    let buf = Buffer.from(plain);
    const k = 2 + Math.floor(rng() * 5);
    const used = [], inter = [buf];
    for (let l = 0; l < k; l++) {
        let t, tries = 0;
        do { t = pick(TRANSFORMS); tries++; } while (tries < 50 && ((t.textOnly && !isPrintable(buf)) || (t.max && buf.length > t.max) || (t.noLeadingZero && buf[0] === 0) || (used.length && used[used.length - 1] === t.id) || (t.id === "reverse" && used.includes("reverse"))));
        if (tries >= 50) break;
        const next = t.make(buf, rng);
        if (next.length > 40000) break;
        buf = next; used.push(t.id); inter.push(buf);
    }
    cases.push({ suite: "layers", label: used.join(" > "), inter: process.env.DUMP ? inter.map(x => x.toString("base64")) : undefined, input: buf, needle: norm(plain).slice(0, 40), lossy: false });
}
// ---- suite 2: classical ciphers on English text, optionally wrapped in 0–2 encodings
const N2 = suiteArg === "classical" ? (nArg || 300) : suiteArg === "all" ? 300 : 0;
for (let i = 0; i < N2; i++) {
    const c = CLASSICAL[i % CLASSICAL.length];
    const plain = pick(prose);
    let buf = Buffer.from(c.make(plain, rng), "latin1");
    const used = [c.id];
    const wraps = Math.floor(rng() * 3);
    for (let w = 0; w < wraps; w++) { const t = pick(TRANSFORMS.filter(x => x.kind === "enc" && !x.textOnly && (!x.max || buf.length <= x.max))); buf = t.make(buf, rng); used.push(t.id); }
    cases.push({ suite: "classical", label: used.join(" > "), input: buf, needle: c.lossy ? lossyNorm(plain).slice(0, 30) : norm(plain).slice(0, 40), lossy: !!c.lossy });
}
// ---- suite 3: keyed encryption, key typed by the user
const N3 = suiteArg === "keyed" ? (nArg || 260) : suiteArg === "all" ? 260 : 0;
for (let i = 0; i < N3; i++) {
    const c = KEYED[i % KEYED.length];
    const plain = pick(rng() < 0.5 ? commands : prose);
    const r = await c.make(Buffer.from(plain), rng, rnd);
    if (!r) continue;
    cases.push({ suite: "keyed", label: c.id, input: Buffer.from(r.text), keys: r.key.split("\n"), needle: norm(plain).slice(0, 40), lossy: false });
}

if (process.env.DUMP) { fs.writeFileSync(process.env.DUMP, JSON.stringify(cases.map(c => ({ ...c, input: c.input.toString("base64") })))); process.exit(0); }
// ONLY=classical,keyed: generate every suite (identical cases) but run only these
if (process.env.ONLY) { const keep = new Set(process.env.ONLY.split(",")); cases.splice(0, cases.length, ...cases.filter(c => keep.has(c.suite))); }
const t0 = Date.now();
const stats = {};
const failures = [];
let n = 0;
for (const c of cases) {
    const res = await autoChef(new Uint8Array(c.input), { timeBudgetMs: 12000, maxResults: 5, keys: c.keys || [] });
    const outs = res.results.map(r => r.output.base64 ? Buffer.from(r.output.base64, "base64").toString("latin1") : (r.output.preview || ""));
    const hit = o => c.lossy ? lossyNorm(o).includes(c.needle) : norm(o).includes(c.needle);
    const ok1 = !!outs[0] && hit(outs[0]), ok5 = outs.some(hit);
    const key = c.suite === "layers" ? `layers (${c.label.split(" > ").length} layers)` : `${c.suite}: ${c.label.split(" > ")[0]}`;
    const s = stats[key] ||= { n: 0, t1: 0, t5: 0, ms: 0 };
    s.n++; s.t1 += ok1; s.t5 += ok5; s.ms += res.stats.ms;
    if (!ok5) failures.push({ suite: c.suite, label: c.label, keys: c.keys, input: c.input.toString("latin1").slice(0, 160), inputB64: c.input.length <= 20000 ? c.input.toString("base64") : undefined, got: res.results[0]?.recipe.map(o => o.op).join(" > ") || null });
    if (process.env.VERBOSE) console.log(n, c.label, ok5 ? "ok" : "FAIL", res.stats.ms + "ms");
    if (++n % 50 === 0) console.log(`${n}/${cases.length}  (${Math.round((Date.now() - t0) / 1000)} s)`);
}
let T1 = 0, T5 = 0;
console.log("\ngroup | top-1 | top-5 | avg ms");
for (const [k, s] of Object.entries(stats).sort()) { console.log(`${k} | ${s.t1}/${s.n} | ${s.t5}/${s.n} | ${Math.round(s.ms / s.n)}`); T1 += s.t1; T5 += s.t5; }
const bySuite = {};
for (const c of cases) bySuite[c.suite] = (bySuite[c.suite] || 0) + 1;
console.log(`\nTOTAL ${cases.length} cases (${Object.entries(bySuite).map(([k, v]) => `${k} ${v}`).join(", ")}): top-1 ${T1} (${(100 * T1 / cases.length).toFixed(1)}%), top-5 ${T5} (${(100 * T5 / cases.length).toFixed(1)}%), ${Math.round((Date.now() - t0) / 1000)} s`);
fs.writeFileSync(path.join(HERE, process.env.ONLY ? `advanced-report-${process.env.ONLY.replace(/,/g, "-")}.json` : "advanced-report.json"), JSON.stringify({ cases: cases.length, top1: T1, top5: T5, stats, failures }, null, 1));
process.exit(0);
