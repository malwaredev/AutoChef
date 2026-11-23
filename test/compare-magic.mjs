/**
 * Baseline: how many samples does CyberChef's own Magic operation solve on its own
 * (depth 3, intensive mode, top 5 suggestions)?
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const Magic = (await import(new URL("../core/lib/Magic.mjs", import.meta.resolve("cyberchef")).href)).default;
const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "samples");
const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
let ok = 0;
for (const m of manifest) {
    const b = fs.readFileSync(path.join(dir, m.file));
    const ab = b.buffer.slice(b.byteOffset, b.byteOffset + b.length);
    let res = [];
    try { res = await new Magic(ab).speculativeExecution(3, true, false, [], false, null); } catch {}
    const hit = res.slice(0, 5).some(r => m.expectFile ? /exe|PE/i.test(JSON.stringify(r.fileType || "")) : String(r.data).includes(m.expect));
    ok += hit;
    console.log(`${hit ? "PASS" : "FAIL"}  ${m.file}`);
}
console.log(`\nCyberChef Magic alone (top-5): ${ok}/${manifest.length}`);
