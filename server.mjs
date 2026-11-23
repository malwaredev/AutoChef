/**
 * AutoChef local web server. Runs only on your machine (127.0.0.1) –
 * samples never leave the computer.
 *
 *   node server.mjs            -> http://127.0.0.1:8471
 *   PORT=9000 node server.mjs
 */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { autoChef, bakeAndScore, listOperations, defaultArgs, opInfo, libraryInfo, aiSuggest, configureAi, aiStatus, listModels, buildReport, REPORT_FORMATS, teamLibraryInfo, saveTeamEntry, deleteTeamEntry, importTeamLibrary, expandZips, analyzeBatch, buildBatchReport, intelLookup, setIntelKeys, intelStatus, runOps } from "./src/index.mjs";
import { tryRunOps } from "./src/chef.mjs";
import { scoreOutput } from "./src/analyze.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8471);
const HOST = process.env.HOST || "127.0.0.1";
const MAX_INPUT = 20 * 1024 * 1024; // 20 MB

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".json": "application/json" };

// The AutoChef browser extension talks to this server from its background worker; the only web
// origin allowed to call the API directly is the official CyberChef site.
const ALLOWED_ORIGINS = new Set(["https://gchq.github.io"]);

function send(res, code, body, type = "application/json") {
    const origin = res.req && res.req.headers.origin;
    const cors = origin && ALLOWED_ORIGINS.has(origin) ? { "Access-Control-Allow-Origin": origin, "Vary": "Origin" } : {};
    res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...cors });
    res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function readBody(req, limit = MAX_INPUT * 1.4) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on("data", c => {
            size += c.length;
            if (size > limit) { reject(new Error("Input too large (max 20 MB)")); req.destroy(); return; }
            chunks.push(c);
        });
        req.on("end", () => resolve(Buffer.concat(chunks)));
        req.on("error", reject);
    });
}

let OPS = null;

const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host}`);
        // refuse requests from other web pages (DNS-rebinding / drive-by protection)
        const origin = req.headers.origin;
        if (origin && !ALLOWED_ORIGINS.has(origin) && origin !== `http://${req.headers.host}` && !origin.startsWith("chrome-extension://") && !origin.startsWith("moz-extension://")) return send(res, 403, { error: "Origin not allowed" });
        if (req.method === "OPTIONS") {
            res.writeHead(204, { "Access-Control-Allow-Origin": ALLOWED_ORIGINS.has(origin) ? origin : "null", "Access-Control-Allow-Methods": "GET, POST, DELETE", "Access-Control-Allow-Headers": "content-type", "Access-Control-Allow-Private-Network": "true" });
            return res.end();
        }
        if (!/^(127\.0\.0\.1|localhost)(:\d+)?$/.test(req.headers.host || "") && HOST === "127.0.0.1") return send(res, 421, { error: "Unexpected Host header" });

        if (req.method === "POST" && url.pathname === "/api/analyze") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const input = new Uint8Array(Buffer.from(body.inputBase64 || "", "base64"));
            if (!input.length) return send(res, 400, { error: "Empty input" });
            if (input.length > MAX_INPUT) return send(res, 413, { error: "Input too large (max 20 MB)" });
            const result = await autoChef(input, {
                crib: String(body.crib || "").slice(0, 200),
                maxDepth: clamp(body.maxDepth, 1, 100, 64),
                timeBudgetMs: clamp(body.timeBudgetMs, 1000, 60000, 12000),
                maxResults: clamp(body.maxResults, 1, 10, 5),
                fileName: String(body.fileName || "").slice(0, 300),
                keys: Array.isArray(body.keys) ? body.keys.map(k => String(k).slice(0, 4096)).filter(k => k.trim()).slice(0, 20) : [],
            });
            return send(res, 200, result);
        }

        if (req.method === "POST" && url.pathname === "/api/bake") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const input = new Uint8Array(Buffer.from(body.inputBase64 || "", "base64"));
            if (!Array.isArray(body.recipe)) return send(res, 400, { error: "recipe must be an array" });
            return send(res, 200, await bakeAndScore(input, body.recipe));
        }

        if (req.method === "POST" && url.pathname === "/api/report") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const bytes = new Uint8Array(Buffer.from(body.inputBase64 || "", "base64"));
            const analysis = body.analysis || await autoChef(bytes, { crib: body.crib || "" });
            const fmt = REPORT_FORMATS.includes(body.format) ? body.format : "json";
            const type = { json: "application/json", csv: "text/csv; charset=utf-8", md: "text/markdown; charset=utf-8", stix: "application/json", misp: "application/json", sigma: "text/yaml; charset=utf-8", yara: "text/plain; charset=utf-8" }[fmt];
            return send(res, 200, buildReport({ name: String(body.name || "input").slice(0, 200), bytes, analysis }, fmt), type);
        }

        if (req.method === "GET" && url.pathname === "/api/library") return send(res, 200, libraryInfo());
        // ---- team library
        if (req.method === "GET" && url.pathname === "/api/team-library") return send(res, 200, teamLibraryInfo());
        if (req.method === "POST" && url.pathname === "/api/team-library") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            try { return send(res, 200, { ok: true, entry: saveTeamEntry(body) }); } catch (e) { return send(res, 400, { error: e.message }); }
        }
        if (req.method === "POST" && url.pathname === "/api/team-library/import") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            return send(res, 200, { ok: true, imported: importTeamLibrary(body) });
        }
        if (req.method === "DELETE" && url.pathname === "/api/team-library") return send(res, 200, { ok: deleteTeamEntry(url.searchParams.get("id") || "") });
        // ---- threat-intel lookups (off until keys are set; one indicator per request)
        if (req.method === "GET" && url.pathname === "/api/intel/status") return send(res, 200, intelStatus());
        if (req.method === "POST" && url.pathname === "/api/intel/keys") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const k = {};
            for (const s of ["virustotal", "abuseipdb", "urlhaus"]) if (s in body) k[s] = body[s] ? String(body[s]).slice(0, 200) : null;
            return send(res, 200, setIntelKeys(k));
        }
        if (req.method === "POST" && url.pathname === "/api/intel/lookup") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const f = { type: String(body.type || ""), value: String(body.value || "").slice(0, 2000), category: String(body.category || "") };
            return send(res, 200, await intelLookup(f));
        }
        // ---- step-by-step bake (each step's output, for the editor)
        if (req.method === "POST" && url.pathname === "/api/bake-steps") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const input = new Uint8Array(Buffer.from(body.inputBase64 || "", "base64"));
            if (!Array.isArray(body.recipe)) return send(res, 400, { error: "recipe must be an array" });
            const steps = [];
            for (let i = 1; i <= Math.min(body.recipe.length, 40); i++) {
                const r = await runPrefix(input, body.recipe.slice(0, i));
                steps.push(r);
                if (!r.ok) break;
            }
            return send(res, 200, { steps });
        }
        // ---- batch: several files (zips expanded, password "infected" by default)
        if (req.method === "POST" && url.pathname === "/api/batch") {
            const body = JSON.parse((await readBody(req, 200 * 1024 * 1024)).toString("utf8"));
            const files = (Array.isArray(body.files) ? body.files : []).slice(0, 500).map(f => ({ name: String(f.name || "file").slice(0, 300), bytes: new Uint8Array(Buffer.from(f.base64 || "", "base64")) })).filter(f => f.bytes.length);
            const items = await expandZips(files, body.password || "infected");
            const batch = await analyzeBatch(items, { timeBudgetMs: clamp(body.timeBudgetMs, 1000, 60000, 8000), keys: Array.isArray(body.keys) ? body.keys.map(String) : [] });
            const fmt = ["md", "csv", "json", "stix", "misp"].includes(body.format) ? body.format : null;
            const rows = batch.map(b => b.analysis ? { name: b.name, size: b.size, sha256: b.sha256, top: b.analysis.results[0] ? { summary: b.analysis.results[0].summary, confidence: b.analysis.results[0].confidence, recipe: b.analysis.results[0].recipeString } : null,
                alerts: b.analysis.alertSummary, ransom: b.analysis.ransom ? b.analysis.ransom.message : null, encrypted: !!b.analysis.assessment, hash: b.analysis.hash ? b.analysis.hash.types[0] : null,
                office: b.analysis.office ? b.analysis.office.modules.length : null, pe: b.analysis.inputPE ? `${b.analysis.inputPE.format} ${b.analysis.inputPE.machine}` : null } : { name: b.name, error: b.error });
            return send(res, 200, { rows, reports: Object.fromEntries(["md", "csv", "json", "stix", "misp"].filter(f => !fmt || f === fmt).map(f => [f, buildBatchReport(batch, f)])) });
        }
        if (req.method === "GET" && url.pathname === "/api/ai/status") return send(res, 200, aiStatus());
        if (req.method === "POST" && (url.pathname === "/api/ai/config" || url.pathname === "/api/ai/key")) {
            // {provider, key, model, baseUrl}: kept in memory only
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const c = {};
            for (const k of ["provider", "key", "model", "baseUrl"]) if (k in body) c[k] = body[k] === null ? null : String(body[k]).slice(0, 2000);
            if (c.baseUrl && !/^https?:\/\/[^\s]+$/i.test(c.baseUrl)) return send(res, 400, { error: "Base URL must start with http:// or https://" });
            return send(res, 200, configureAi(c));
        }
        if (req.method === "GET" && url.pathname === "/api/ai/models") return send(res, 200, await listModels());
        if (req.method === "POST" && url.pathname === "/api/ai/suggest") {
            const body = JSON.parse((await readBody(req)).toString("utf8"));
            const input = new Uint8Array(Buffer.from(body.inputBase64 || "", "base64"));
            return send(res, 200, await aiSuggest(input, body.results || []));
        }

        if (req.method === "GET" && url.pathname === "/api/operations") return send(res, 200, OPS ||= await listOperations());
        if (req.method === "GET" && url.pathname === "/api/op-info") return send(res, 200, (await opInfo(url.searchParams.get("op") || "")) || { error: "Unknown operation" });
        if (req.method === "GET" && url.pathname === "/api/default-args") return send(res, 200, (await defaultArgs(url.searchParams.get("op") || "")) || []);

        if (req.method === "GET") {
            const rel = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
            const file = path.normalize(path.join(ROOT, "public", rel));
            if (!file.startsWith(path.join(ROOT, "public")) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, { error: "Not found" });
            return send(res, 200, fs.readFileSync(file), MIME[path.extname(file)] || "application/octet-stream");
        }
        send(res, 405, { error: "Method not allowed" });
    } catch (e) {
        send(res, 500, { error: String(e.message || e) });
    }
});

function clamp(v, lo, hi, def) {
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : def;
}

/** output after a recipe prefix (for the editor's step-by-step view) */
async function runPrefix(input, ops) {
    const r = await tryRunOps(input, ops);
    if (!r.ok) return { ok: false, error: r.error };
    const b = Buffer.from(r.bytes), sc = scoreOutput(r.bytes);
    const isText = sc.info.kind === "text" || sc.info.kind === "encoded-text";
    return { ok: true, size: b.length, isText, kind: sc.info.kind, preview: isText ? b.subarray(0, 3000).toString("utf8") : b.subarray(0, 256).toString("hex") };
}

server.listen(PORT, HOST, () => {
    console.log(`AutoChef is running:  http://${HOST}:${PORT}`);
    console.log("Press Ctrl+C to stop.");
});
