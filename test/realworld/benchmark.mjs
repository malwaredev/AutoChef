/**
 * Real-world benchmark on REAL malware samples.
 *
 * Source: https://github.com/mattnotmax/cyberchef-recipes, a public collection of
 * CyberChef recipes written by analysts for real malware samples (password-protected
 * zips, password "infected"). That repository has no licence file, so we do NOT copy
 * it into this project: this script downloads it into test/realworld/.cache at run time.
 *
 * For each recipe that decodes something, the analyst's own recipe is run through
 * CyberChef to produce the reference answer (trailing post-processing steps such as
 * "Extract URLs", "Defang" or "To Hexdump" are dropped). AutoChef then gets ONLY the
 * raw sample and must reach the same content.
 *
 * Samples are only read as data. Nothing is executed.
 *
 *   node test/realworld/benchmark.mjs            (downloads on first run, needs git)
 *   node test/realworld/benchmark.mjs 30         (only recipe 30)
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { BlobReader, ZipReader, Uint8ArrayWriter } from "@zip.js/zip.js";
import { autoChef } from "../../src/index.mjs";
import { tryRunOps } from "../../src/chef.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, ".cache");
const REPO = path.join(CACHE, "cyberchef-recipes");
const only = process.argv[2] ? Number(process.argv[2]) : null;

// steps that only post-process an already-decoded result
const POST_OPS = new Set(["Extract URLs", "Extract IP addresses", "Extract domains", "Extract email addresses", "Extract file paths",
    "Defang URL", "Defang IP Addresses", "Strings", "To Hexdump", "Generic Code Beautify", "JavaScript Beautify", "Disassemble x86",
    "Detect File Type", "Entropy", "Sort", "Unique", "Count occurrences", "Filter", "YARA Rules", "To Table", "Parse User Agent",
    "Syntax highlighter", "Remove whitespace", "Remove null bytes", "Head", "Tail", "Comment", "Render Image", "Parse X.509 certificate",
    "Fang URL", "PHP Deserialize", "JSON Beautify", "XML Beautify", "Extract Files", "From UNIX Timestamp", "Parse IPv4 header",
    "Translate DateTime Format", "Scan for Embedded Files", "Find / Replace", "SHA0", "SHA1", "SHA2", "SHA3", "MD5", "MD4", "MD2", "Generate all hashes", "Analyse hash", "SSDEEP", "CTPH", "To Hex"]);

// recipes that parse/format data rather than decode an obfuscated payload
const PARSING_OPS = new Set(["Windows Filetime to UNIX Timestamp", "From UNIX Timestamp", "Parse DateTime", "Translate DateTime Format",
    "Parse IPv4 header", "Parse TLV", "Generate QR Code", "Pseudo-Random Number Generator", "HTTP request"]);

if (!fs.existsSync(REPO)) {
    fs.mkdirSync(CACHE, { recursive: true });
    console.log("Downloading https://github.com/mattnotmax/cyberchef-recipes …");
    execFileSync("git", ["clone", "--depth", "1", "https://github.com/mattnotmax/cyberchef-recipes.git", REPO], { stdio: "inherit" });
}

// ---------- parse the analysts' recipes ----------
const md = fs.readFileSync(path.join(REPO, "README.md"), "utf8");
const parts = md.split(/\n##\s+Recipe\s+(\d+)\s*-\s*/);
const recipes = [];
for (let i = 1; i < parts.length; i += 2) {
    const num = Number(parts[i]), body = parts[i + 1];
    const m = body.match(/`+\s*(\[\{[\s\S]*?\}\])\s*`+/);
    let recipe = null;
    try { recipe = m ? JSON.parse(m[1]) : null; } catch { recipe = null; }
    recipes.push({ num, title: body.split("\n")[0].trim(), recipe, filename: (body.match(/Filename:\s*(.+)/) || [])[1]?.trim() });
}

// ---------- unpack samples (AES zips, password "infected", sometimes nested / gzipped) ----------
async function unpack(zipBytes, depth = 0) {
    const files = [];
    const reader = new ZipReader(new BlobReader(new Blob([zipBytes])), { password: "infected" });
    for (const e of await reader.getEntries()) {
        if (e.directory) continue;
        let data = await e.getData(new Uint8ArrayWriter());
        const name = e.filename;
        if (data[0] === 0x50 && data[1] === 0x4b && depth < 3 && !/\.(docx|docm|xlsx|xlsm|pptx)$/i.test(name)) {
            try { files.push(...await unpack(data, depth + 1)); continue; } catch { /* not an archive we can open */ }
        }
        if (data[0] === 0x1f && data[1] === 0x8b && /\.gz$/i.test(name)) {
            const zlib = await import("node:zlib");
            files.push({ name: name.replace(/\.gz$/i, ""), data: new Uint8Array(zlib.gunzipSync(data)) });
            continue;
        }
        files.push({ name, data });
    }
    await reader.close();
    return files;
}

/** Recipes saved with older CyberChef versions: convert argument lists that changed since. */
function upgradeArgs(o) {
    if (o.op === "AES Decrypt" && o.args.length === 7) {
        // old: Key, IV, Mode, Input, Output, GCM Tag, AAD  →  new: Key, IV, IV length, Mode, Input, Output, GCM Tag, AAD, IV from input
        const [key, iv, mode, input, output, tag, aad] = o.args;
        return { ...o, args: [key, iv, 16, mode, input, output, tag, typeof aad === "object" ? aad : { option: "Hex", string: aad || "" }, "Off"] };
    }
    return o;
}

const tokensOf = s => new Set((s.match(/[A-Za-z0-9_.:\/\\-]{6,}/g) || []).filter(t => /[A-Za-z]/.test(t)));
const latin1 = b => Buffer.from(b).toString("latin1");

function coverage(refText, outText, inputText) {
    const inTok = tokensOf(inputText);
    const ref = [...tokensOf(refText)].filter(t => !inTok.has(t) && !inputText.includes(t)).slice(0, 400);
    if (ref.length < 3) return null; // the analyst recipe didn't reveal anything new
    const hits = ref.filter(t => outText.includes(t)).length;
    return hits / ref.length;
}

const report = [];
let evaluated = 0, top1 = 0, top5 = 0;
for (const r of recipes) {
    if (only && r.num !== only) continue;
    const zip = path.join(REPO, "source_files", `recipe_${r.num}.zip`);
    if (!r.recipe || !fs.existsSync(zip)) continue;
    if (r.recipe.some(o => PARSING_OPS.has(o.op))) { report.push({ recipe: r.num, title: r.title, status: "skip", why: "parsing task, not decoding" }); continue; }
    const files = (await unpack(fs.readFileSync(zip))).filter(f => f.data.length > 0 && f.data.length < 4_000_000);
    if (!files.length) continue;
    let decodeOps = [...r.recipe];
    while (decodeOps.length && POST_OPS.has(decodeOps[decodeOps.length - 1].op)) decodeOps.pop();
    decodeOps = decodeOps.map(o => ({ ...o, disabled: undefined, breakpoint: undefined })).map(upgradeArgs);

    for (const f of files.slice(0, 3)) {
        const ref = decodeOps.length ? await tryRunOps(f.data, decodeOps, 30000) : { ok: false };
        if (!ref.ok) { report.push({ recipe: r.num, title: r.title, file: f.name, status: "skip", why: "analyst recipe does not run on this file" }); continue; }
        const inputText = latin1(f.data), refText = latin1(ref.bytes);
        if (ref.bytes.length < 200 && /^(Unable to|Error|Invalid)/i.test(refText)) {
            // the published recipe no longer runs correctly in today's CyberChef (argument / padding changes)
            const res = await autoChef(f.data, { timeBudgetMs: 25000, useLibrary: !process.env.NO_LIBRARY });
            report.push({ recipe: r.num, title: r.title, file: f.name, status: "skip", why: `analyst recipe fails in current CyberChef ("${refText.trim()}"); AutoChef result: ${res.results[0] ? res.results[0].summary + " via " + res.results[0].recipe.map(o => o.op).join(" → ") : "none"}` });
            console.log(`NOTE  #${r.num} ${r.title}: ${report[report.length - 1].why}`);
            break;
        }
        if (coverage(refText, refText, inputText) === null) { report.push({ recipe: r.num, title: r.title, file: f.name, status: "skip", why: "not a decoding task" }); continue; }

        const res = await autoChef(f.data, { timeBudgetMs: 25000, useLibrary: !process.env.NO_LIBRARY });
        const covs = res.results.map(x => coverage(refText, x.output.base64 ? Buffer.from(x.output.base64, "base64").toString("latin1") : (x.output.preview || ""), inputText) || 0);
        const c1 = covs[0] || 0, c5 = Math.max(0, ...covs);
        const ok1 = c1 >= 0.6, ok5 = c5 >= 0.6;
        evaluated++; top1 += ok1; top5 += ok5;
        report.push({ recipe: r.num, title: r.title, file: f.name, status: ok1 ? "pass" : ok5 ? "top5" : "fail", coverageTop1: +c1.toFixed(2), coverageTop5: +c5.toFixed(2),
            analystRecipe: decodeOps.map(o => o.op).join(" → "), autochefRecipe: res.results[0]?.recipe.map(o => o.op).join(" → ") || null, ms: res.stats.ms });
        const last = report[report.length - 1];
        console.log(`${last.status.toUpperCase().padEnd(5)} #${String(r.num).padEnd(3)} ${r.title.slice(0, 55).padEnd(55)} top1=${last.coverageTop1} top5=${last.coverageTop5}`);
        console.log(`        analyst : ${last.analystRecipe}`);
        console.log(`        autochef: ${last.autochefRecipe}`);
        break; // one file per recipe
    }
}
fs.writeFileSync(path.join(HERE, "benchmark-report.json"), JSON.stringify({ evaluated, top1, top5, report }, null, 2));
console.log(`\nReal-world malware samples evaluated: ${evaluated}`);
console.log(`AutoChef reached the analyst's result: top-1 ${top1}/${evaluated}, top-5 ${top5}/${evaluated}`);
console.log(`Skipped (not decoding tasks / recipe needs other input): ${report.filter(x => x.status === "skip").length}`);
process.exit(0);
