/**
 * Plugins in the browser edition: the bundled plugins are always loaded; a user can add a plugin
 * file for the current session (it runs as code in this page, so the UI asks for confirmation).
 */
import exfil from "../../plugins/exfil-channels.mjs";
const plugins = [{ file: "exfil-channels.mjs", ...exfil }];
const warned = new Set();
export function loadPlugins() { return Promise.resolve(plugins); }
export async function addPluginFromText(name, code) {
    const url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
    try {
        const m = await import(/* @vite-ignore */ url);
        const p = m.default;
        if (!p || typeof p.name !== "string" || (typeof p.candidates !== "function" && typeof p.findings !== "function")) throw new Error("no valid default export");
        plugins.push({ file: name, ...p });
        return p.name;
    } finally { URL.revokeObjectURL(url); }
}
export function pluginInfo() { return { dir: "(bundled with the site; extra plugins can be added for this session)", plugins: plugins.map(p => ({ file: p.file, name: p.name, version: p.version || "", description: p.description || "", candidates: typeof p.candidates === "function", findings: typeof p.findings === "function" })) }; }
function guard(p, kind, fn) { try { const r = fn(); return Array.isArray(r) ? r : []; } catch (e) { const k = p.name + kind; if (!warned.has(k)) { warned.add(k); console.warn(`[plugins] ${p.name}.${kind}: ${e.message}`); } return []; } }
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
