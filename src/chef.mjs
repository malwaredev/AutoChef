/**
 * Access to the official CyberChef engine.
 *  - Recipes run in worker threads (src/pool.mjs) through CyberChef's core Chef class,
 *    exactly like the CyberChef web app (flow control such as Subsection/Fork included),
 *    with a timeout so hostile input can't hang AutoChef.
 *  - The Node API is used in-process only for metadata (operation list, argument defaults).
 */
import { getPool } from "./pool.mjs";

// The full Node API is loaded lazily (only the recipe editor needs it), keeping the main process light.
let chefApi = null;
async function api() { if (!chefApi) chefApi = (await import("cyberchef")).default; return chefApi; }

export const DEFAULT_OP_TIMEOUT = Number(process.env.AUTOCHEF_OP_TIMEOUT_MS) || 5000;

function toArrayBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/** Run a recipe on raw bytes. Never throws: returns {ok, bytes} or {ok:false, error}. */
export async function tryRunOps(bytes, ops, timeoutMs = DEFAULT_OP_TIMEOUT) {
    const r = await getPool().run({ kind: "bake", input: toArrayBuffer(bytes), recipe: ops }, timeoutMs);
    if (!r.ok) return { ok: false, error: r.error, timeout: !!r.timeout, failedStep: r.failedStep };
    return { ok: true, bytes: new Uint8Array(r.result) };
}

/** Same as tryRunOps but throws on error. */
export async function runOps(bytes, ops, timeoutMs) {
    const r = await tryRunOps(bytes, ops, timeoutMs);
    if (!r.ok) throw new Error(r.error);
    return r.bytes;
}

/** CyberChef's own Magic operation, run in a worker. Returns a list of recipes. */
export async function magicRecipes(bytes, { depth = 3, intensive = false, crib = "" } = {}, timeoutMs = 8000) {
    const r = await getPool().run({ kind: "magic", input: toArrayBuffer(bytes), depth, intensive, crib }, timeoutMs);
    return r.ok ? r.result : [];
}

/** List of every CyberChef operation name (for the recipe editor). */
export async function listOperations() {
    const chef = await api();
    const names = new Set();
    for (const v of Object.values(chef)) {
        if (typeof v !== "function" || !v.opName) continue;
        // v.opName is the JS identifier (e.g. "RC4Drop"); the recipe needs CyberChef's display name ("RC4 Drop")
        let name = v.opName;
        try { name = chef.help(v.opName)[0]?.name || name; } catch { /* keep identifier */ }
        names.add(name);
    }
    for (const fc of ["Fork", "Merge", "Subsection", "Register", "Label", "Jump", "Conditional Jump", "Return", "Comment"]) names.add(fc);
    return [...names].sort((a, b) => a.localeCompare(b));
}

/** Default argument values for an operation (for the recipe editor). */
export async function defaultArgs(opName) {
    const chef = await api();
    let h;
    try { h = chef.help(opName); } catch { h = null; }
    if (!h || !h[0]) return FLOW_DEFAULTS[opName] || null;
    return h[0].args.map(a => {
        if (a.type === "toggleString") return { option: (a.toggleValues || [""])[0], string: a.value ?? "" };
        if (Array.isArray(a.value)) {
            const first = a.value[0];
            return typeof first === "object" && first !== null ? (first.value ?? first.name) : first;
        }
        return a.value;
    });
}

/** Argument metadata for the editor's typed widgets: [{name, type, options?, toggleValues?, value}] */
export async function opInfo(opName) {
    const chef = await api();
    let h;
    try { h = chef.help(opName); } catch { h = null; }
    const defaults = await defaultArgs(opName);
    if (!h || !h[0]) {
        if (!FLOW_DEFAULTS[opName]) return null;
        return { name: opName, description: "", args: FLOW_DEFAULTS[opName].map((v, i) => ({ name: `Argument ${i + 1}`, type: typeof v === "boolean" ? "boolean" : typeof v === "number" ? "number" : "string", value: v })) };
    }
    return {
        name: h[0].name || opName,
        description: String(h[0].description || "").replace(/<br\s*\/?>|<\/?(p|li|ul|ol)>/gi, " ").replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim().slice(0, 400),
        args: h[0].args.map((a, i) => {
            const o = { name: a.name, type: a.type, value: defaults[i] };
            if (a.type === "toggleString") o.toggleValues = a.toggleValues || [];
            if (Array.isArray(a.value)) o.options = a.value.map(v => typeof v === "object" && v !== null ? { name: v.name, value: v.value ?? v.name } : { name: String(v), value: v });
            return o;
        }),
    };
}

const FLOW_DEFAULTS = {
    "Fork": ["\\n", "\\n", false],
    "Merge": [true],
    "Subsection": ["", true, true, false],
    "Register": ["([\\s\\S]*)", true, false, false],
    "Label": [""],
    "Jump": ["", 10],
    "Conditional Jump": ["", false, "", 10],
    "Return": [],
    "Comment": [""],
};
