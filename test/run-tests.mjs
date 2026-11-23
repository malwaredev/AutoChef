/**
 * Runs AutoChef against every sample in test/samples and checks whether the
 * known answer appears in the #1 result (top-1) or anywhere in the top 5.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { autoChef } from "../src/search.mjs";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "samples");
const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
const only = process.argv[2];

const hit = (r, m) => {
    if (!r) return false;
    if (m.expectFile) return !!r.output.fileType && /PE|executable/i.test(r.output.fileType);
    return (r.output.preview || "").includes(m.expect);
};

let top1 = 0, top5 = 0;
for (const m of manifest) {
    if (only && !m.file.includes(only)) continue;
    const input = new Uint8Array(fs.readFileSync(path.join(dir, m.file)));
    const res = await autoChef(input, { timeBudgetMs: 15000 });
    const best = res.results[0];
    const ok1 = hit(best, m);
    const ok5 = res.results.some(r => hit(r, m));
    top1 += ok1; top5 += ok5;
    console.log(`${ok1 ? "PASS" : ok5 ? "TOP5" : "FAIL"}  ${m.file.padEnd(36)} ${String(res.stats.ms).padStart(5)}ms  ${best ? best.recipe.map(o => o.op).join(" → ") : "(no result)"}`);
    if (!ok1 && process.env.VERBOSE) console.log(JSON.stringify(res.results.map(r => ({ s: r.score, rec: r.recipeString, out: (r.output.preview || r.output.hexPreview || "").slice(0, 80) })), null, 1));
}
const n = only ? manifest.filter(m => m.file.includes(only)).length : manifest.length;
console.log(`\nTop-1 accuracy: ${top1}/${n}   Top-5 accuracy: ${top5}/${n}`);
process.exitCode = top5 === n ? 0 : 1;
