// node:fs for the browser build. Bundled data files are served from the bundle; the team
// library is kept in the browser's localStorage (per browser, per site).
import recipes from "../../library/recipes.json";
import signatures from "../../ransom/signatures.json";
const BUNDLED = { "recipes.json": JSON.stringify(recipes), "signatures.json": JSON.stringify(signatures) };
const KEY = p => "autochef:file:" + String(p).split(/[\\/]/).pop();
const ls = () => { try { return globalThis.localStorage; } catch { return null; } };
export function readFileSync(p) {
    const name = String(p instanceof URL ? p.pathname : p).split(/[\\/]/).pop();
    if (name in BUNDLED) return BUNDLED[name];
    const v = ls()?.getItem(KEY(p));
    if (v === null || v === undefined) { const e = new Error(`ENOENT: ${name}`); e.code = "ENOENT"; throw e; }
    return v;
}
export function writeFileSync(p, data) { ls()?.setItem(KEY(p), typeof data === "string" ? data : new TextDecoder().decode(data)); }
export function renameSync(a, b) { const s = ls(); if (!s) return; const v = s.getItem(KEY(a)); if (v !== null) { s.setItem(KEY(b), v); s.removeItem(KEY(a)); } }
export function mkdirSync() {}
export function existsSync(p) { const name = String(p).split(/[\\/]/).pop(); return name in BUNDLED || ls()?.getItem(KEY(p)) != null; }
export function readdirSync() { return []; }
export function statSync() { return { isDirectory: () => false, isFile: () => true, size: 0 }; }
export function unlinkSync(p) { ls()?.removeItem(KEY(p)); }
export default { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, readdirSync, statSync, unlinkSync };
