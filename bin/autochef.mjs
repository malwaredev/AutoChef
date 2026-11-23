#!/usr/bin/env node
/**
 * AutoChef command line.
 *
 *   node bin/autochef.mjs sample.txt
 *   node bin/autochef.mjs --text "SGVsbG8="
 *   type payload.ps1 | node bin/autochef.mjs -          (Windows)
 *   node bin/autochef.mjs samples\*.txt --json > report.json
 *   node bin/autochef.mjs payload.bin --save out\       (write decoded outputs)
 *
 *   node bin/autochef.mjs payload.ps1 --report md --out report.md
 *
 * Options: --crib <text>  --depth <n>  --time <ms>  --top <n>  --json  --save <dir>
 *          --report md|csv|json  --out <file>  --no-library  --no-magic
 *          --key <key|password|IV>   (repeatable: text, hex or Base64; a 2nd key of IV size is used as IV)
 *          --report md|csv|json|stix|misp|sigma|yara
 *
 * Batch mode (folders, many files, zips – password "infected" by default):
 *   node bin/autochef.mjs --batch samples\ --report md --out batch.md
 *   node bin/autochef.mjs --batch incident.zip --zip-password infected --report misp --out event.json
 *   Batch reports: md, csv, json, stix, misp.
 *
 * Team library:   --library-add "<name>" --recipe '<CyberChef recipe JSON>' [--family F] [--detect REGEX]
 *                 --library-list    --library-remove <id>
 */
import fs from "node:fs";
import path from "node:path";
import { autoChef, buildReport, teamLibraryInfo, saveTeamEntry, deleteTeamEntry } from "../src/index.mjs";
import { readFolder, expandZips, analyzeBatch, buildBatchReport } from "../src/batch.mjs";

process.stdout.on("error", e => { if (e.code === "EPIPE") process.exit(0); throw e; }); // e.g. piping into head

const argv = process.argv.slice(2);
const flags = {}; const files = [];
for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") flags.json = true;
    else if (a === "--no-library") flags.noLibrary = true;
    else if (a === "--no-magic") flags.noMagic = true;
    else if (a === "--report" || a === "--out") flags[a.slice(2)] = argv[++i];
    else if (a === "--key") (flags.keys ||= []).push(argv[++i]);
    else if (a === "--detect") (flags.detect ||= []).push(argv[++i]);
    else if (a === "--batch") flags.batch = true;
    else if (a === "--library-list") flags.libraryList = true;
    else if (["--zip-password", "--library-add", "--library-remove", "--recipe", "--family", "--notes"].includes(a)) flags[a.slice(2).replace(/-(\w)/g, (m, c) => c.toUpperCase())] = argv[++i];
    else if (["--crib", "--depth", "--time", "--top", "--text", "--save"].includes(a)) flags[a.slice(2)] = argv[++i];
    else if (a === "-h" || a === "--help") flags.help = true;
    else files.push(a);
}

// ---- team library management
if (flags.libraryList) { const t = teamLibraryInfo(); console.log(`Team library: ${t.file}`); for (const e of t.entries) console.log(`  ${e.id}  ${e.name}${e.family ? " (" + e.family + ")" : ""}  ${e.recipe.map(o => o.op).join(" > ")}`); process.exit(0); }
if (flags.libraryRemove) { console.log(deleteTeamEntry(flags.libraryRemove) ? "removed" : "no such entry"); process.exit(0); }
if (flags.libraryAdd) {
    let recipe;
    try { recipe = JSON.parse(flags.recipe || ""); } catch { console.error("--recipe must be a CyberChef recipe in JSON (CyberChef: Save recipe → JSON)"); process.exit(1); }
    console.log(saveTeamEntry({ name: flags.libraryAdd, family: flags.family, notes: flags.notes, detect: flags.detect, recipe: recipe.map(o => ({ op: o.op, args: o.args || [] })) }));
    process.exit(0);
}

if (flags.help || (!files.length && flags.text === undefined)) {
    console.log(fs.readFileSync(new URL(import.meta.url), "utf8").split("*/")[0].replace(/^#!.*\n\/\*\*?/, "").replace(/^ \* ?/gm, ""));
    process.exit(0);
}

const searchOptions = () => ({
    crib: flags.crib || "", keys: flags.keys || [],
    maxDepth: flags.depth ? Number(flags.depth) : undefined, timeBudgetMs: flags.time ? Number(flags.time) : undefined,
    maxResults: flags.top ? Number(flags.top) : undefined, useLibrary: !flags.noLibrary, useMagic: !flags.noMagic,
});

// ---- batch mode
if (flags.batch) {
    let items = [];
    for (const f of files) items.push(...(fs.statSync(f).isDirectory() ? readFolder(f) : [{ name: path.basename(f), bytes: new Uint8Array(fs.readFileSync(f)) }]));
    items = await expandZips(items, flags.zipPassword || "infected");
    const batch = await analyzeBatch(items, searchOptions(), (i, n, name) => process.stderr.write(`[${i + 1}/${n}] ${name}\n`));
    const fmt = flags.report || "md";
    if (!["md", "csv", "json", "stix", "misp"].includes(fmt)) { console.error("batch reports: md, csv, json, stix, misp"); process.exit(1); }
    const rep = buildBatchReport(batch, fmt);
    if (flags.out) { fs.writeFileSync(flags.out, rep); console.error(`Wrote ${flags.out} (${batch.length} files)`); } else process.stdout.write(rep + "\n");
    process.exit(0);
}

const inputs = [];
if (flags.text !== undefined) inputs.push({ name: "(text)", bytes: new Uint8Array(Buffer.from(flags.text, "utf8")) });
for (const f of files) {
    if (f === "-") inputs.push({ name: "(stdin)", bytes: new Uint8Array(fs.readFileSync(0)) });
    else inputs.push({ name: f, bytes: new Uint8Array(fs.readFileSync(f)) });
}

const report = [];
for (const { name, bytes } of inputs) {
    const res = await autoChef(bytes, { ...searchOptions(), fileName: name });
    if (flags.report) {
        const rep = buildReport({ name, bytes, analysis: res }, flags.report);
        if (flags.out) { fs.writeFileSync(inputs.length > 1 ? flags.out.replace(/(\.\w+)?$/, `.${path.basename(name).replace(/[^\w.-]/g, "_")}$1`) : flags.out, rep); }
        else process.stdout.write(rep + "\n");
        continue;
    }
    if (flags.save && res.results[0]) {
        fs.mkdirSync(flags.save, { recursive: true });
        res.results.forEach((r, i) => {
            if (!r.output.base64) return;
            const out = path.join(flags.save, `${path.basename(name).replace(/[^\w.-]/g, "_")}.result${i + 1}.bin`);
            fs.writeFileSync(out, Buffer.from(r.output.base64, "base64"));
        });
    }
    if (flags.json) {
        report.push({ file: name, ...res, results: res.results.map(r => ({ ...r, output: { ...r.output, base64: undefined } })) });
        continue;
    }
    const enc = res.assessment ? `  [ENCRYPTED] ${res.assessment.message}` : res.hash ? `  [HASH] ${res.hash.message}` : null;
    console.log(`\n=== ${name}  (${bytes.length} bytes, ${res.stats.explored} candidates explored in ${res.stats.ms} ms)`);
    if (enc) console.log(enc);
    if (res.ransom) console.log(`  [RANSOM NOTE] ${res.ransom.message}`);
    if (res.office) console.log(`  [OFFICE] ${res.office.container}: ${res.office.modules.length} VBA module(s)${res.office.embedded.length ? ", " + res.office.embedded.length + " link(s)/macro sheet(s)/strings" : ""}`);
    if (res.inputPE) console.log(`  [PE] ${peLine(res.inputPE)}`);
    if (res.alerts?.length) {
        const s = res.alertSummary;
        console.log(`  [ALERT] ${s.high} high, ${s.medium} medium, ${s.info} info findings: ${Object.entries(s.byType).map(([k, v]) => `${k} ×${v}`).join(", ")}`);
        for (const a of res.alerts.filter(a => a.level === "high").slice(0, 15)) console.log(`    ! ${a.type}: ${a.value}${a.note ? "  (" + a.note + ")" : ""}`);
    }
    if (!res.results.length) { console.log(res.input?.info?.script ? `  The input is already readable ${res.input.info.script} text; no hidden layer was found.` : "  No convincing decoding found. Try --crib with text you expect in the output."); continue; }
    if (res.libraryMatches?.length) console.log(`  Known pattern(s): ${res.libraryMatches.map(m => `${m.name} — ${m.source.url}`).join("; ")}`);
    res.results.forEach((r, i) => {
        console.log(`\n#${i + 1}  [${r.confidence.toUpperCase()} ${r.score}]  ${r.summary}`);
        r.steps.forEach((s, j) => console.log(`   ${j + 1}. ${s.ops.join(" + ")}${s.times ? " ×" + s.times : ""}  — ${s.why}`));
        if (r.loop) console.log(`   ↻ ${r.loop}`);
        const prev = r.output.isText ? r.output.preview.slice(0, 300).replace(/\s+/g, " ") : `hex: ${r.output.hexPreview.slice(0, 96)}…`;
        console.log(`   Output: ${prev}`);
        const byT = {};
        for (const f of r.output.findings || []) (byT[f.type] ||= []).push(f.value);
        for (const [k, v] of Object.entries(byT)) console.log(`   ${k}: ${v.slice(0, 8).join(", ")}${v.length > 8 ? " …" : ""}`);
        if (r.output.pe) console.log(`   PE: ${peLine(r.output.pe)}`);
        if (r.output.readable) console.log(`   Readable view: ${r.output.readable.slice(0, 400).replace(/\s+/g, " ")}`);
        console.log(`   Recipe: ${r.recipeString}`);
        console.log(`   Open in CyberChef: ${r.cyberChefUrl.length > 2000 ? r.cyberChefUrl.split("&input=")[0] + "  (input too long for URL; paste it manually)" : r.cyberChefUrl}`);
    });
}
if (flags.json) console.log(JSON.stringify(report, null, 2));

function peLine(p) {
    return `${p.format} ${p.type} ${p.machine}${p.dotnet ? " .NET" : ""}, compiled ${p.compiled.slice(0, 10)}, imphash ${p.imphash || "-"}, ${p.sections.length} sections, ${p.imports.length} DLLs${p.notableImports.length ? ", notable imports: " + p.notableImports.slice(0, 8).join(" ") : ""}${p.pdb ? ", PDB " + p.pdb : ""}${p.warnings.length ? " — " + p.warnings.join("; ") : ""}`;
}
