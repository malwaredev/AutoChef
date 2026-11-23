/**
 * Plugin interface. Every *.mjs file in plugins/ (or in the folder named by AUTOCHEF_PLUGINS)
 * is loaded once at start-up. A plugin's default export is an object:
 *
 *   export default {
 *     name: "my-plugin", version: "1.0.0", description: "what it adds",
 *     // optional: propose CyberChef steps for some data. ctx = {prevOps, rootText, parentText, keys}
 *     candidates(bytes, ctx) { return [{ ops: [{op: "From Base64", args: [...]}], why: "…", prior: 10 }]; },
 *     // optional: extra findings in decoded text
 *     findings(text) { return [{ category: "network", type: "Telegram bot token", value: "…", level: "high", note: "…" }]; },
 *   };
 *
 * Plugins run inside AutoChef with the same rights as AutoChef: install only plugins you trust.
 * A plugin that throws is skipped for that call and reported once on the console.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DIR = process.env.AUTOCHEF_PLUGINS || path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "plugins");
let plugins = [];
let loaded = null;
const warned = new Set();

export function loadPlugins() {
    if (loaded) return loaded;
    loaded = (async () => {
        let files = [];
        try { files = fs.readdirSync(DIR).filter(f => f.endsWith(".mjs")).sort(); } catch { return plugins; }
        for (const f of files) {
            try {
                const m = await import(pathToFileURL(path.join(DIR, f)).href);
                const p = m.default;
                if (!p || typeof p.name !== "string" || (typeof p.candidates !== "function" && typeof p.findings !== "function")) { console.warn(`[plugins] ${f}: no valid default export, skipped`); continue; }
                plugins.push({ file: f, ...p });
            } catch (e) { console.warn(`[plugins] ${f}: ${e.message}`); }
        }
        return plugins;
    })();
    return loaded;
}
export function pluginInfo() { return { dir: DIR, plugins: plugins.map(p => ({ file: p.file, name: p.name, version: p.version || "", description: p.description || "", candidates: typeof p.candidates === "function", findings: typeof p.findings === "function" })) }; }

function guard(p, kind, fn) {
    try { const r = fn(); return Array.isArray(r) ? r : []; }
    catch (e) { const k = p.name + kind; if (!warned.has(k)) { warned.add(k); console.warn(`[plugins] ${p.name}.${kind}: ${e.message}`); } return []; }
}
export function pluginCandidates(bytes, ctx) {
    const out = [];
    for (const p of plugins) if (p.candidates) for (const c of guard(p, "candidates", () => p.candidates(bytes, ctx)))
        if (c && Array.isArray(c.ops) && c.ops.every(o => o && typeof o.op === "string" && Array.isArray(o.args))) out.push({ ops: c.ops, why: `${c.why || ""} [plugin: ${p.name}]`, prior: Math.min(25, Number(c.prior) || 8), source: `Plugin: ${p.name}` });
    return out;
}
export function pluginFindings(text) {
    const out = [];
    for (const p of plugins) if (p.findings) for (const f of guard(p, "findings", () => p.findings(text)))
        if (f && f.type && f.value) out.push({ category: String(f.category || "plugin"), type: String(f.type), value: String(f.value), level: ["high", "medium", "info"].includes(f.level) ? f.level : "info", note: [f.note, `plugin ${p.name}`].filter(Boolean).join("; ") });
    return out;
}
