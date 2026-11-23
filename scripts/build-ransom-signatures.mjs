/**
 * Builds src/ransom/signatures.json from two public sources:
 *   - ransom notes collected by Zscaler ThreatLabz (MIT): https://github.com/ThreatLabz/ransomware_notes
 *   - the list of free decryptors on No More Ransom: https://www.nomoreransom.org/en/decryption-tools.html
 *
 *   git clone --depth 1 https://github.com/ThreatLabz/ransomware_notes /tmp/rn
 *   curl -L -o /tmp/nmr.html https://www.nomoreransom.org/en/decryption-tools.html
 *   node scripts/build-ransom-signatures.mjs /tmp/rn /tmp/nmr.html
 *
 * Per family it keeps: note file names, contact points written in the notes (onion sites, e-mail
 * addresses, Tox IDs, other URLs) and a few long lines that appear in no other family's notes.
 */
import fs from "node:fs";
import path from "node:path";

const [notesDir, nmrFile] = process.argv.slice(2);
if (!notesDir || !nmrFile) { console.error("usage: node scripts/build-ransom-signatures.mjs <ransomware_notes dir> <nomoreransom decryption-tools.html>"); process.exit(1); }
const families = fs.readdirSync(notesDir).filter(d => !d.startsWith(".") && fs.statSync(path.join(notesDir, d)).isDirectory());
const read = f => { const b = fs.readFileSync(f); return b[1] === 0 && b[3] === 0 ? b.toString("utf16le") : b.toString("utf8"); };
const norm = l => l.replace(/\s+/g, " ").trim();
const fam = {};
const lineOwners = new Map();
for (const f of families) {
    const files = fs.readdirSync(path.join(notesDir, f)).filter(x => fs.statSync(path.join(notesDir, f, x)).isFile());
    const text = files.map(x => read(path.join(notesDir, f, x))).join("\n");
    const plain = text.replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ");
    fam[f] = {
        family: f, notes: files,
        onions: [...new Set(plain.match(/\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b/gi) || [])].map(x => x.toLowerCase()),
        emails: [...new Set((plain.match(/\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b/gi) || []).map(x => x.toLowerCase()))].filter(e => !/example|domain\.com|mail\.com$/.test(e)),
        tox: [...new Set(plain.match(/\b[0-9A-F]{76}\b/g) || [])],
        norm: norm(plain).toLowerCase(),
        lines: [...new Set(plain.split(/\r?\n/).map(norm).filter(l => l.length >= 45 && l.length <= 200 && /[a-z]{4}/i.test(l)))],
    };
    for (const l of fam[f].lines) { const k = l.toLowerCase(); if (!lineOwners.has(k)) lineOwners.set(k, new Set()); lineOwners.get(k).add(f); }
}
// keep only lines unique to one family, and drop very generic ones
const GENERIC = /^(all your (important )?files|your files (are|have been) encrypted|do not (rename|modify|try)|what happened|how to (recover|decrypt)|contact us|attention|warning)/i;
// a phrase must not occur anywhere in another family's notes (not even inside a longer line)
for (const f of families) fam[f].phrases = fam[f].lines.filter(l => lineOwners.get(l.toLowerCase()).size === 1 && !GENERIC.test(l) && !families.some(g => g !== f && fam[g].norm.includes(l.toLowerCase()))).sort((a, b) => b.length - a.length).slice(0, 6);
// contact points shared by several families (reused templates) are not evidence for one of them
for (const k of ["onions", "emails", "tox"]) for (const f of families) fam[f][k] = fam[f][k].filter(x => !families.some(g => g !== f && fam[g].norm.includes(x.toLowerCase())));
// No More Ransom: families with a free decryptor
const nmr = fs.readFileSync(nmrFile, "utf8");
const tools = [...nmr.matchAll(/<button[^>]*class="expandable-toggler"[^>]*id="([^"]+)"[^>]*>([^<]+)<\/button>/g)].map(m => ({ id: m[1], name: m[2].replace(/\s+/g, " ").replace(/ Ransom$/, "").trim() }));
const key = s => s.toLowerCase().replace(/[^a-z0-9]/g, "");
const out = {
    generated: new Date().toISOString().slice(0, 10),
    sources: { notes: "https://github.com/ThreatLabz/ransomware_notes (MIT, Zscaler ThreatLabz)", decryptors: "https://www.nomoreransom.org/en/decryption-tools.html" },
    decryptors: tools.map(t => ({ name: t.name, url: `https://www.nomoreransom.org/en/decryption-tools.html#${t.id}` })),
    families: families.map(f => {
        const d = fam[f];
        // same name, or the same name plus a version ("LockBit 3.0" for "lockbit"); never a loose prefix
        const t = tools.find(t => key(t.name) === key(f) || (key(f).length >= 4 && new RegExp(`^${key(f)}(v?\\d+)*$`).test(key(t.name))));
        return { family: f, nmrName: t ? t.name : null, notes: d.notes.filter(n => !/^(readme|notes?)\.(md|txt)$/i.test(n)).slice(0, 12), onions: d.onions.slice(0, 20), emails: d.emails.slice(0, 20), tox: d.tox.slice(0, 5), phrases: d.phrases, decryptor: t ? `https://www.nomoreransom.org/en/decryption-tools.html#${t.id}` : null };
    }).filter(f => f.onions.length || f.emails.length || f.tox.length || f.phrases.length),
};
fs.writeFileSync(new URL("../src/ransom/signatures.json", import.meta.url), JSON.stringify(out, null, 1));
console.log(`families: ${out.families.length}, with a No More Ransom decryptor: ${out.families.filter(f => f.decryptor).length}, decryptor list: ${out.decryptors.length}`);
