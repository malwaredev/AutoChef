/**
 * Large-scale test: real attacker commands (Atomic Red Team, MIT) obfuscated with
 * real-world chains (chains.mjs), then given to AutoChef. A case passes when the
 * original command appears in AutoChef's output.
 *
 *   node test/corpus/run-corpus.mjs            1200 cases (seeded, reproducible)
 *   node test/corpus/run-corpus.mjs 300 42     300 cases, seed 42
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CHAINS } from "./chains.mjs";
import { autoChef } from "../../src/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const N = Number(process.argv[2]) || 1200;
let seed = Number(process.argv[3]) || 1337;
const only = process.env.CHAIN || null;
const rng = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
const rnd = n => Buffer.from(Array.from({ length: n }, () => Math.floor(rng() * 256)));

const commands = JSON.parse(fs.readFileSync(path.join(HERE, "art-commands.json"), "utf8"))
    .map(c => c.command.replace(/\r\n/g, "\n"))
    .filter(c => c.length >= 40 && c.length <= 1500 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(c));
const chains = only ? CHAINS.filter(c => c.id === only) : CHAINS;

const norm = s => s.replace(/\s+/g, " ").trim();
const cases = [];
for (let i = 0; i < N; i++) {
    const chain = chains[i % chains.length];
    const cmd = commands[Math.floor(rng() * commands.length)];
    const data = chain.make(cmd, rng, rnd);
    const firstLine = norm(cmd.split("\n").find(l => l.trim().length >= 20) || cmd);
    cases.push({ i, chain: chain.id, ref: chain.ref, cmd, data, needle: firstLine.slice(0, chain.needlePart ? 20 : 40) });
}

const t0 = Date.now();
const stats = {};
const failures = [];
let top1 = 0, top5 = 0;
for (const c of cases) {
    const bytes = new Uint8Array(Buffer.isBuffer(c.data) ? c.data : Buffer.from(c.data, "utf8"));
    const res = await autoChef(bytes, { timeBudgetMs: 10000, maxResults: 5 });
    const outs = res.results.map(r => norm(r.output.base64 ? Buffer.from(r.output.base64, "base64").toString("utf8") : (r.output.preview || "")));
    const h1 = !!outs[0] && outs[0].includes(c.needle);
    const h5 = outs.some(o => o.includes(c.needle));
    top1 += h1; top5 += h5;
    const st = stats[c.chain] ||= { ref: c.ref, n: 0, top1: 0, top5: 0, ms: 0 };
    st.n++; st.top1 += h1; st.top5 += h5; st.ms += res.stats.ms;
    if (!h5 && process.env.VERBOSE) { console.log("FAIL", c.chain, JSON.stringify(c.needle)); for (const r of res.results) console.log("   ", r.score, r.recipe.map(o => o.op).join(" > "), JSON.stringify((r.output.preview || r.output.hexPreview || "").slice(0, 100))); }
    if (!h5) failures.push({ chain: c.chain, needle: c.needle, input: String(c.data).slice(0, 200), got: res.results[0]?.recipeString?.slice(0, 200) || null });
    if ((c.i + 1) % 50 === 0) console.log(`${c.i + 1}/${cases.length}  top-1 ${top1}  top-5 ${top5}  (${Math.round((Date.now() - t0) / 1000)} s)`);
}
console.log("\nPer chain (top-1 / top-5 / avg ms):");
for (const [id, s] of Object.entries(stats)) console.log(`  ${id.padEnd(18)} ${String(s.top1).padStart(3)}/${s.n}  ${String(s.top5).padStart(3)}/${s.n}  ${Math.round(s.ms / s.n)} ms   ${s.ref}`);
console.log(`\nTOTAL ${cases.length} cases: top-1 ${top1} (${(100 * top1 / cases.length).toFixed(1)}%), top-5 ${top5} (${(100 * top5 / cases.length).toFixed(1)}%), ${Math.round((Date.now() - t0) / 1000)} s`);
fs.writeFileSync(path.join(HERE, "corpus-report.json"), JSON.stringify({ cases: cases.length, top1, top5, stats, failures }, null, 1));
process.exit(0);
