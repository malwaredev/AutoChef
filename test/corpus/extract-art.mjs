/**
 * Extracts real attacker command lines from Atomic Red Team (MIT licence,
 * https://github.com/redcanaryco/atomic-red-team) into art-commands.json.
 * Default input arguments are substituted so commands look as they would run.
 *
 *   git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /tmp/art
 *   node test/corpus/extract-art.mjs /tmp/art
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as yaml from "js-yaml";

const root = process.argv[2];
if (!root) { console.error("usage: node extract-art.mjs <atomic-red-team checkout>"); process.exit(1); }
const dir = path.join(root, "atomics");
const out = [];
for (const t of fs.readdirSync(dir).sort()) {
    const f = path.join(dir, t, `${t}.yaml`);
    if (!fs.existsSync(f)) continue;
    let doc;
    try { doc = yaml.load(fs.readFileSync(f, "utf8")); } catch { continue; }
    for (const at of doc.atomic_tests || []) {
        let cmd = at.executor && at.executor.command;
        if (!cmd || typeof cmd !== "string") continue;
        for (const [k, v] of Object.entries(at.input_arguments || {})) cmd = cmd.split(`#{${k}}`).join(String(v.default ?? ""));
        cmd = cmd.trim();
        if (cmd.length < 40 || cmd.length > 4000 || /#\{/.test(cmd)) continue;
        out.push({ technique: t, name: at.name, description: String(at.description || "").replace(/\s+/g, " ").trim().slice(0, 600), executor: at.executor.name, platforms: at.supported_platforms, command: cmd });
    }
}
const target = path.join(path.dirname(fileURLToPath(import.meta.url)), "art-commands.json");
fs.writeFileSync(target, JSON.stringify(out, null, 1));
console.log(`Extracted ${out.length} commands from ${new Set(out.map(o => o.technique)).size} techniques -> ${target}`);
