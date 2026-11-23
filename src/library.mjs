/**
 * Recipe library: known obfuscation patterns from published analyses (src/library/recipes.json).
 * When an input matches an entry's detection patterns, that entry's recipe is proposed with a
 * high prior and the result is labelled with the family and the public source.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const data = JSON.parse(fs.readFileSync(new URL("./library/recipes.json", import.meta.url), "utf8"));

export const LIBRARY = data.entries.map(e => ({ ...e, _re: e.detect.map(d => new RegExp(d, "im")) }));

/** Entries whose detection patterns all match the input text (Latin-1 view of the bytes). */
export function matchLibrary(text) {
    return LIBRARY.filter(e => e._re.every(r => r.test(text)));
}

export function libraryCandidates(text) {
    return matchLibrary(text).filter(e => e.recipe).map(e => ({
        ops: e.recipe.map(o => ({ op: o.op, args: o.args })),
        why: `Matches a known pattern: ${e.name} (${e.family}). Recipe from: ${e.source.title}`,
        prior: 25,
        source: "Recipe library",
        library: { id: e.id, name: e.name, family: e.family, source: e.source },
    }));
}

export function libraryInfo() {
    return LIBRARY.map(({ _re, ...e }) => e);
}

// ---------- team library: recipes saved by your analysts ----------
// Stored as JSON in data/team-library.json (or AUTOCHEF_LIBRARY), so a team can keep it in a
// shared folder or in git. Entries with detection patterns are tried when they match; entries
// without patterns are tried on every input (they are cheap: one CyberChef bake each).
const TEAM_FILE = process.env.AUTOCHEF_LIBRARY || path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "data", "team-library.json");
let team = null;
function loadTeam() {
    if (team) return team;
    try { team = JSON.parse(fs.readFileSync(TEAM_FILE, "utf8")).entries || []; } catch { team = []; }
    for (const e of team) e._re = (e.detect || []).map(d => { try { return new RegExp(d, "im"); } catch { return null; } }).filter(Boolean);
    return team;
}
function saveTeam() {
    fs.mkdirSync(path.dirname(TEAM_FILE), { recursive: true });
    const tmp = TEAM_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ format: "autochef-team-library/1", entries: team.map(({ _re, ...e }) => e) }, null, 2));
    fs.renameSync(tmp, TEAM_FILE);
}
export function teamLibraryInfo() { return { file: TEAM_FILE, entries: loadTeam().map(({ _re, ...e }) => e) }; }

/** Add or replace an entry: {name, family?, notes?, recipe:[{op,args}], detect?:[regex], author?} */
export function saveTeamEntry(e) {
    loadTeam();
    if (!e || typeof e.name !== "string" || !e.name.trim()) throw new Error("name is required");
    if (!Array.isArray(e.recipe) || !e.recipe.length || !e.recipe.every(o => o && typeof o.op === "string" && Array.isArray(o.args))) throw new Error("recipe must be a non-empty list of {op, args}");
    const detect = (e.detect || []).map(String).filter(Boolean).slice(0, 10);
    for (const d of detect) new RegExp(d); // throws on invalid patterns
    const id = e.id || e.name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) + "-" + Date.now().toString(36);
    const entry = { id, name: e.name.trim().slice(0, 200), family: String(e.family || "").slice(0, 200), notes: String(e.notes || "").slice(0, 4000),
        author: String(e.author || "").slice(0, 200), created: e.created || new Date().toISOString(), updated: new Date().toISOString(),
        detect, recipe: e.recipe.map(o => ({ op: o.op, args: o.args })) };
    const i = team.findIndex(x => x.id === id);
    if (i >= 0) team[i] = entry; else team.push(entry);
    entry._re = detect.map(d => new RegExp(d, "im"));
    saveTeam();
    const { _re, ...clean } = entry;
    return clean;
}
export function deleteTeamEntry(id) {
    loadTeam();
    const n = team.length;
    team = team.filter(e => e.id !== id);
    if (team.length !== n) saveTeam();
    return n !== team.length;
}
/** Merge entries from an exported team library (same id = replaced) */
export function importTeamLibrary(obj) {
    const list = Array.isArray(obj) ? obj : obj && Array.isArray(obj.entries) ? obj.entries : [];
    let n = 0;
    for (const e of list) { try { saveTeamEntry(e); n++; } catch { /* skip invalid */ } }
    return n;
}
export function teamCandidates(text) {
    return loadTeam()
        .filter(e => !e._re.length || e._re.every(r => r.test(text)))
        .slice(0, 60)
        .map(e => ({
            ops: e.recipe.map(o => ({ op: o.op, args: o.args })),
            why: `Team library: ${e.name}${e.family ? " (" + e.family + ")" : ""}${e._re.length ? " — detection patterns match" : ""}${e.notes ? ". " + e.notes.slice(0, 200) : ""}`,
            prior: e._re.length ? 28 : 12,
            source: "Team library",
            library: { id: e.id, name: e.name, family: e.family || "team library", source: { title: `Team library${e.author ? " — " + e.author : ""}`, url: "" }, team: true },
        }));
}
