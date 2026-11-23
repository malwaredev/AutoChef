/**
 * Browser edition entry point. The web page (public/index.html) talks to "/api/…" exactly as it
 * does with the local server; here those calls are answered inside the page by the same engine,
 * so nothing is uploaded anywhere. Exposed as window.AutoChef for scripting and tests.
 */
import { autoChef, bakeAndScore } from "../search.mjs";
import { listOperations, defaultArgs, opInfo, tryRunOps } from "../chef.mjs";
import { scoreOutput } from "../analyze.mjs";
import { libraryInfo, teamLibraryInfo, saveTeamEntry, deleteTeamEntry, importTeamLibrary } from "../library.mjs";
import { buildReport, REPORT_FORMATS } from "../report.mjs";
import { aiSuggest, configureAi, aiStatus, listModels } from "../ai.mjs";
import { lookup, intelStatus, setIntelKeys } from "../intel.mjs";
import { expandZips, analyzeBatch, buildBatchReport } from "../batch.mjs";
import { pluginInfo, addPluginFromText } from "../plugins.mjs";
import { extractFindings, cryptoAddresses } from "../findings.mjs";
import { extractOffice } from "../office.mjs";
import { analyzePE } from "../pe.mjs";
import { identifyRansom } from "../ransom.mjs";
import { scriptKeyCandidates } from "../crypto.mjs";
import { parseUserKeys } from "../userkeys.mjs";
import { fastSolve } from "../fastpath.mjs";
import { magicRecipes } from "../chef.mjs";
import cryptoShim from "crypto";

const MAX_INPUT = 20 * 1024 * 1024;
const b64 = s => new Uint8Array(Buffer.from(s || "", "base64"));
const clamp = (v, lo, hi, d) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };
let OPS = null;

async function runPrefix(input, ops) {
    const r = await tryRunOps(input, ops);
    if (!r.ok) return { ok: false, error: r.error };
    const b = Buffer.from(r.bytes), sc = scoreOutput(r.bytes);
    const isText = sc.info.kind === "text" || sc.info.kind === "encoded-text";
    return { ok: true, size: b.length, isText, kind: sc.info.kind, preview: isText ? b.subarray(0, 3000).toString("utf8") : b.subarray(0, 256).toString("hex") };
}

/** The same routes as server.mjs; returns [status, body, contentType] */
export async function handle(method, path, body) {
    const url = new URL(path, "http://local/");
    const p = url.pathname, q = url.searchParams;
    const json = body ? JSON.parse(body) : {};
    if (method === "POST" && p === "/api/analyze") {
        const input = b64(json.inputBase64);
        if (!input.length) return [400, { error: "Empty input" }];
        if (input.length > MAX_INPUT) return [413, { error: "Input too large (max 20 MB)" }];
        return [200, await autoChef(input, { crib: String(json.crib || "").slice(0, 200), maxDepth: clamp(json.maxDepth, 1, 100, 64), timeBudgetMs: clamp(json.timeBudgetMs, 1000, 60000, 12000), maxResults: clamp(json.maxResults, 1, 10, 5), fileName: String(json.fileName || ""), keys: Array.isArray(json.keys) ? json.keys.map(String).filter(k => k.trim()).slice(0, 20) : [] })];
    }
    if (method === "POST" && p === "/api/bake") return [200, await bakeAndScore(b64(json.inputBase64), json.recipe || [])];
    if (method === "POST" && p === "/api/bake-steps") {
        const input = b64(json.inputBase64), steps = [];
        for (let i = 1; i <= Math.min((json.recipe || []).length, 40); i++) { const r = await runPrefix(input, json.recipe.slice(0, i)); steps.push(r); if (!r.ok) break; }
        return [200, { steps }];
    }
    if (method === "POST" && p === "/api/report") {
        const bytes = b64(json.inputBase64);
        const fmt = REPORT_FORMATS.includes(json.format) ? json.format : "json";
        const type = { json: "application/json", csv: "text/csv", md: "text/markdown", stix: "application/json", misp: "application/json", sigma: "text/yaml", yara: "text/plain" }[fmt];
        return [200, buildReport({ name: String(json.name || "input"), bytes, analysis: json.analysis || await autoChef(bytes, {}) }, fmt), type];
    }
    if (method === "GET" && p === "/api/library") return [200, libraryInfo()];
    if (method === "GET" && p === "/api/team-library") return [200, teamLibraryInfo()];
    if (method === "POST" && p === "/api/team-library") { try { return [200, { ok: true, entry: saveTeamEntry(json) }]; } catch (e) { return [400, { error: e.message }]; } }
    if (method === "POST" && p === "/api/team-library/import") return [200, { ok: true, imported: importTeamLibrary(json) }];
    if (method === "DELETE" && p === "/api/team-library") return [200, { ok: deleteTeamEntry(q.get("id") || "") }];
    if (method === "GET" && p === "/api/intel/status") return [200, intelStatus()];
    if (method === "POST" && p === "/api/intel/keys") return [200, setIntelKeys(json)];
    if (method === "POST" && p === "/api/intel/lookup") return [200, await lookup({ type: String(json.type || ""), value: String(json.value || ""), category: String(json.category || "") })];
    if (method === "GET" && p === "/api/ai/status") return [200, { ...aiStatus(), browser: true }];
    if (method === "POST" && (p === "/api/ai/config" || p === "/api/ai/key")) return [200, configureAi(json)];
    if (method === "GET" && p === "/api/ai/models") return [200, await listModels()];
    if (method === "POST" && p === "/api/ai/suggest") return [200, await aiSuggest(b64(json.inputBase64), json.results || [])];
    if (method === "GET" && p === "/api/operations") return [200, OPS ||= await listOperations()];
    if (method === "GET" && p === "/api/op-info") return [200, (await opInfo(q.get("op") || "")) || { error: "Unknown operation" }];
    if (method === "GET" && p === "/api/default-args") return [200, (await defaultArgs(q.get("op") || "")) || []];
    if (method === "GET" && p === "/api/plugins") return [200, pluginInfo()];
    if (method === "POST" && p === "/api/batch") {
        const files = (json.files || []).slice(0, 500).map(f => ({ name: String(f.name || "file"), bytes: b64(f.base64) })).filter(f => f.bytes.length);
        const items = await expandZips(files, json.password || "infected");
        const batch = await analyzeBatch(items, { timeBudgetMs: clamp(json.timeBudgetMs, 1000, 60000, 8000), keys: Array.isArray(json.keys) ? json.keys.map(String) : [] });
        const rows = batch.map(b => b.analysis ? { name: b.name, size: b.size, sha256: b.sha256, top: b.analysis.results[0] ? { summary: b.analysis.results[0].summary, confidence: b.analysis.results[0].confidence, recipe: b.analysis.results[0].recipeString } : null,
            alerts: b.analysis.alertSummary, ransom: b.analysis.ransom ? b.analysis.ransom.message : null, encrypted: !!b.analysis.assessment, hash: b.analysis.hash ? b.analysis.hash.types[0] : null,
            office: b.analysis.office ? b.analysis.office.modules.length : null, pe: b.analysis.inputPE ? `${b.analysis.inputPE.format} ${b.analysis.inputPE.machine}` : null } : { name: b.name, error: b.error });
        return [200, { rows, reports: Object.fromEntries(["md", "csv", "json", "stix", "misp"].map(f => [f, buildBatchReport(batch, f)])) }];
    }
    if (method === "GET" && p === "/api/edition") return [200, { edition: "browser" }];
    return [404, { error: "Not found" }];
}

/** Answer the page's fetch("/api/…") calls in the page itself */
export function installApi() {
    const realFetch = globalThis.fetch.bind(globalThis);
    globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input.url;
        const u = new URL(url, location.href);
        if (u.origin !== location.origin || !u.pathname.startsWith("/api/") && !u.pathname.includes("/api/")) return realFetch(input, init);
        const path = u.pathname.slice(u.pathname.indexOf("/api/")) + u.search;
        try {
            const [status, body, type = "application/json"] = await handle((init.method || "GET").toUpperCase(), path, init.body);
            return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": type } });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
        }
    };
}

export { autoChef, bakeAndScore, buildReport, extractFindings, cryptoAddresses, extractOffice, analyzePE, identifyRansom, addPluginFromText };
globalThis.AutoChef = { autoChef, bakeAndScore, buildReport, extractFindings, cryptoAddresses, extractOffice, analyzePE, identifyRansom, addPluginFromText, handle, edition: "browser", _internals: { fastSolve, magicRecipes, scriptKeyCandidates, parseUserKeys, crypto: cryptoShim } };
installApi();
// start the CyberChef workers while the page is idle (parsing the bundle takes a few seconds)
import("../chef.mjs").then(() => import("./pool.mjs")).then(m => m.getPool().warm()).catch(() => {});
