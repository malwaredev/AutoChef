/**
 * Verifies every recipe-library entry against the REAL sample that accompanies its
 * published source (downloaded by test/realworld/benchmark.mjs into test/realworld/.cache).
 * An entry passes when (1) its detection patterns match the sample and (2) its recipe,
 * run by CyberChef, reveals the same content as the analyst's original recipe.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BlobReader, ZipReader, Uint8ArrayWriter } from "@zip.js/zip.js";
import zlib from "node:zlib";
import { libraryInfo, matchLibrary } from "../../src/library.mjs";
import { tryRunOps } from "../../src/chef.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, "..", "realworld", ".cache", "cyberchef-recipes");
if (!fs.existsSync(REPO)) { console.log("Run test/realworld/benchmark.mjs once first (it downloads the samples)."); process.exit(1); }

async function unpack(bytes, depth = 0) {
    const out = [];
    const r = new ZipReader(new BlobReader(new Blob([bytes])), { password: "infected" });
    for (const e of await r.getEntries()) {
        if (e.directory) continue;
        const d = await e.getData(new Uint8ArrayWriter());
        if (d[0] === 0x50 && d[1] === 0x4b && depth < 3 && !/\.(docx|docm|xlsx|xlsm)$/i.test(e.filename)) { try { out.push(...await unpack(d, depth + 1)); continue; } catch {} }
        if (d[0] === 0x1f && d[1] === 0x8b && /\.gz$/i.test(e.filename)) { out.push({ name: e.filename.slice(0, -3), data: new Uint8Array(zlib.gunzipSync(d)) }); continue; }
        out.push({ name: e.filename, data: d });
    }
    await r.close();
    return out;
}

const md = fs.readFileSync(path.join(REPO, "README.md"), "utf8");
const analyst = {};
const parts = md.split(/\n##\s+Recipe\s+(\d+)\s*-\s*/);
for (let i = 1; i < parts.length; i += 2) { const m = parts[i + 1].match(/`+\s*(\[\{[\s\S]*?\}\])\s*`+/); try { analyst[parts[i]] = JSON.parse(m[1]); } catch {} }
const POST = new Set(["Extract URLs", "Defang URL", "Strings", "To Hexdump", "Generic Code Beautify", "Disassemble x86", "Extract IP addresses", "Extract domains", "Register", "Split", "Filter", "Unique", "Sort"]);
const tokens = s => new Set((s.match(/[A-Za-z0-9_.:\/\\-]{6,}/g) || []).filter(t => /[A-Za-z]/.test(t)));

let pass = 0, total = 0;
for (const e of libraryInfo()) {
    if (!e.recipe || !e.sample) continue;
    total++;
    const files = (await unpack(fs.readFileSync(path.join(REPO, "source_files", `recipe_${e.sample.recipe}.zip`)))).filter(f => f.data.length < 4e6);
    let ok = false, detail = "";
    for (const f of files) {
        const text = Buffer.from(f.data).toString("latin1");
        const detected = matchLibrary(text).some(m => m.id === e.id);
        if (!detected) { detail = `patterns do not match ${f.name}`; continue; }
        const mine = await tryRunOps(f.data, e.recipe, 30000);
        let ref = (analyst[e.sample.recipe] || []).map(o => ({ ...o, disabled: undefined }));
        while (ref.length && POST.has(ref[ref.length - 1].op)) ref.pop();
        const theirs = await tryRunOps(f.data, ref, 30000);
        if (!mine.ok) { detail = `recipe failed: ${mine.error}`; continue; }
        const refTok = theirs.ok ? [...tokens(Buffer.from(theirs.bytes).toString("latin1"))].filter(t => !text.includes(t)).slice(0, 300) : [];
        const out = Buffer.from(mine.bytes).toString("latin1");
        const cov = refTok.length ? refTok.filter(t => out.includes(t)).length / refTok.length : (mine.bytes.length ? 1 : 0);
        detail = `${f.name}: coverage of analyst result ${(cov * 100).toFixed(0)}%`;
        if (cov >= 0.6) { ok = true; break; }
    }
    pass += ok;
    console.log(`${ok ? "PASS" : "FAIL"}  ${e.id.padEnd(32)} ${detail}`);
}
console.log(`\nLibrary entries verified on real samples: ${pass}/${total}`);
process.exit(pass === total ? 0 : 1);
