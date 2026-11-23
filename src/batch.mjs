/**
 * Batch mode: many samples at once (a folder, a list of files, or a .zip – also password-protected
 * zips such as the usual "infected" malware archives), one combined report.
 */
import fs from "node:fs";
import path from "node:path";
import { ZipReader, Uint8ArrayReader, Uint8ArrayWriter } from "@zip.js/zip.js";
import { autoChef } from "./search.mjs";
import { buildReport, defang, sha256 } from "./report.mjs";

const isZip = b => b.length > 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4;
const OFFICE_ZIP = /\.(docx|docm|dotm|xlsx|xlsm|xlsb|xltm|pptx|pptm|potm|ppsm)$/i;

/** Expand zips (not Office documents) into their files. items: [{name, bytes}] */
export async function expandZips(items, password = "infected", depth = 0) {
    const out = [];
    for (const it of items) {
        if (depth < 2 && isZip(it.bytes) && !OFFICE_ZIP.test(it.name)) {
            try {
                const entries = await new ZipReader(new Uint8ArrayReader(it.bytes), { password }).getEntries();
                // an Office Open XML file named .zip is still a document
                if (entries.some(e => e.filename === "[Content_Types].xml")) { out.push(it); continue; }
                const inner = [];
                for (const e of entries) if (!e.directory && e.uncompressedSize < 64 << 20) inner.push({ name: `${it.name}/${e.filename}`, bytes: await e.getData(new Uint8ArrayWriter(), { password }) });
                out.push(...await expandZips(inner, password, depth + 1));
                continue;
            } catch (e) { out.push({ ...it, error: `zip: ${e.message}` }); continue; }
        }
        out.push(it);
    }
    return out;
}

/** Files of a folder (recursive, up to `max`) */
export function readFolder(dir, max = 2000) {
    const out = [];
    const walk = d => { for (const n of fs.readdirSync(d)) { if (out.length >= max) return; const p = path.join(d, n); const st = fs.statSync(p); if (st.isDirectory()) walk(p); else if (st.size > 0 && st.size <= 64 << 20) out.push({ name: path.relative(dir, p), bytes: new Uint8Array(fs.readFileSync(p)) }); } };
    walk(dir);
    return out;
}

/** Analyse every item; onProgress(i, n, name) */
export async function analyzeBatch(items, options = {}, onProgress = () => {}) {
    const out = [];
    for (const [i, it] of items.entries()) {
        onProgress(i, items.length, it.name);
        if (it.error) { out.push({ name: it.name, error: it.error }); continue; }
        try {
            const analysis = await autoChef(it.bytes, { ...options, fileName: it.name });
            out.push({ name: it.name, size: it.bytes.length, sha256: sha256(it.bytes), analysis, bytes: it.bytes });
        } catch (e) { out.push({ name: it.name, error: e.message }); }
    }
    return out;
}

/** Combined report: md, csv, json, stix, misp (alerts of all samples; recipes per sample) */
export function buildBatchReport(batch, format = "md") {
    const ok = batch.filter(b => b.analysis);
    if (format === "json") return JSON.stringify(batch.map(b => b.analysis ? { name: b.name, size: b.size, sha256: b.sha256, ...b.analysis, results: b.analysis.results.map(r => ({ ...r, output: { ...r.output, base64: undefined } })) } : b), null, 2);
    if (format === "csv") {
        const rows = ["file,sha256,alert_level,type,value,note"];
        const cell = v => /[",\n\r]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v);
        for (const b of ok) for (const a of b.analysis.alerts || []) rows.push([b.name, b.sha256, a.level, a.type, a.value, a.note || ""].map(cell).join(","));
        return rows.join("\r\n") + "\r\n";
    }
    if (format === "stix" || format === "misp") {
        // one bundle / event: merge the alerts of all samples, note which file each came from
        const alerts = [], seen = new Set();
        for (const b of ok) for (const a of b.analysis.alerts || []) { const k = a.type + "|" + a.value; if (!seen.has(k)) { seen.add(k); alerts.push({ ...a, note: [a.note, `in ${b.name}`].filter(Boolean).join("; ") }); } }
        const all = Buffer.concat(ok.map(b => Buffer.from(b.sha256)));
        return buildReport({ name: `batch of ${ok.length} files`, bytes: all, analysis: { results: [], alerts } }, format);
    }
    // Markdown
    const L = [`# AutoChef batch report`, "", `- **Generated:** ${new Date().toISOString()}`, `- **Files:** ${batch.length} (${ok.length} analysed, ${batch.length - ok.length} errors)`, ""];
    L.push("| File | Result | Confidence | High | Medium | Ransom family | Notes |", "|---|---|---|---|---|---|---|");
    for (const b of batch) {
        if (!b.analysis) { L.push(`| ${b.name} | error: ${b.error} | | | | | |`); continue; }
        const a = b.analysis, r = a.results[0], s = a.alertSummary || { high: 0, medium: 0 };
        const notes = [a.assessment && "encrypted, no key", a.hash && `hash (${a.hash.types[0]})`, a.office && `${a.office.modules.length} macro module(s)`, a.inputPE && `PE ${a.inputPE.machine}`].filter(Boolean).join(", ");
        L.push(`| ${b.name.replace(/\|/g, "\\|")} | ${r ? r.summary.replace(/\|/g, "\\|") : "nothing decoded"} | ${r ? r.confidence : ""} | ${s.high} | ${s.medium} | ${a.ransom?.families?.[0]?.family || ""} | ${notes} |`);
    }
    L.push("");
    const allHigh = [];
    for (const b of ok) for (const a of b.analysis.alerts || []) if (a.level === "high") allHigh.push([b.name, a]);
    if (allHigh.length) {
        L.push("## High-level findings (defanged)", "", "| File | Type | Value |", "|---|---|---|");
        for (const [n, a] of allHigh) L.push(`| ${n} | ${a.type} | \`${a.category === "network" ? defang(a.value) : a.value}\` |`);
        L.push("");
    }
    for (const b of ok) {
        const r = b.analysis.results.find(x => x.recipeString);
        if (r) L.push(`### ${b.name}`, "", `SHA-256 \`${b.sha256}\` — ${r.summary}`, "", "```", r.recipeString, "```", "");
    }
    return L.join("\n");
}
