/**
 * Runs the two post-install fixes CyberChef needs when used as a library
 * (normally done by its grunt-based postinstall script).
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scripts = path.join(root, "node_modules", "cyberchef", "src", "core", "config", "scripts");

for (const s of ["fixCryptoApiImports.mjs", "fixSnackBarMarkup.mjs"]) {
    const p = path.join(scripts, s);
    if (!fs.existsSync(p)) { console.warn(`skip: ${s} not found`); continue; }
    try {
        execFileSync(process.execPath, [p], { cwd: root, stdio: "inherit" });
        console.log(`ok: ${s}`);
    } catch (e) {
        console.warn(`warning: ${s} failed (${e.message}). AutoChef may still work.`);
    }
}

// smoke test
const { default: chef } = await import("cyberchef");
const out = await chef.bake("QXV0b0NoZWYgaXMgcmVhZHk=", [{ op: "From Base64", args: ["A-Za-z0-9+/=", true, false] }]);
console.log(String(out));
