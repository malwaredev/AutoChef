/**
 * Ransom-note identification. Signatures (src/ransom/signatures.json) are built by
 * scripts/build-ransom-signatures.mjs from the ThreatLabz ransomware_notes collection (MIT) and
 * the No More Ransom decryptor list. Evidence is exact: an onion site, e-mail address or Tox ID
 * written in the note, or a line that occurs in that family's notes only.
 */
import fs from "node:fs";

const SIG = JSON.parse(fs.readFileSync(new URL("./ransom/signatures.json", import.meta.url), "utf8"));
const norm = s => s.replace(/\s+/g, " ").toLowerCase();
const PREP = SIG.families.map(f => ({ ...f, _phrases: f.phrases.map(norm), _notes: f.notes.map(n => n.toLowerCase()) }));
const NOTE_WORDS = /(your (important )?(files|data|network)( and \w+)? (have been|are|were) (encrypted|stolen|locked)|tor browser|\.onion\b|decrypt(ion|or)? (tool|software|key)|bitcoin|ransom|recover your files|leak(ed)? (site|blog)|unique (id|key)|do not (rename|modify) (the )?(encrypted )?files)/gi;

export const CRYPTO_SHERIFF = "https://www.nomoreransom.org/crypto-sheriff.php";

/** {isNote, families:[{family, score, evidence, decryptor, nmrName}], sources, generated} or null */
export function identifyRansom(text, fileName = "") {
    if (!text || text.length < 80) return null;
    const t = text.slice(0, 300000), n = norm(t), lowerName = String(fileName).toLowerCase().split(/[\\/]/).pop();
    const hits = [];
    for (const f of PREP) {
        const ev = [];
        let score = 0;
        for (const o of f.onions) if (n.includes(o)) { score += 3; ev.push(`onion site ${o}`); }
        for (const e of f.emails) if (n.includes(e)) { score += 3; ev.push(`contact e-mail ${e}`); }
        for (const x of f.tox) if (t.includes(x)) { score += 3; ev.push(`Tox ID ${x.slice(0, 12)}…`); }
        for (const p of f._phrases) if (n.includes(p)) { score += 2; ev.push(`phrase "${p.slice(0, 70)}${p.length > 70 ? "…" : ""}"`); }
        if (lowerName && f._notes.includes(lowerName)) { score += 1; ev.push(`note file name ${lowerName}`); }
        if (score >= 2) hits.push({ family: f.family, score, evidence: ev.slice(0, 6), decryptor: f.decryptor, nmrName: f.nmrName });
    }
    hits.sort((a, b) => b.score - a.score);
    const words = new Set((t.match(NOTE_WORDS) || []).map(w => w.toLowerCase())).size;
    const isNote = hits.length > 0 || words >= 3;
    if (!isNote) return null;
    return { isNote, families: hits.slice(0, 3), noteWords: words, sources: SIG.sources, generated: SIG.generated, cryptoSheriff: CRYPTO_SHERIFF };
}

/** Message for people: what was found and where a decryptor may exist */
export function ransomMessage(r) {
    if (!r) return null;
    if (!r.families.length) return `This looks like a ransom note, but it matches no family in the signature set (${r.generated}). Upload it with an encrypted file to No More Ransom's Crypto Sheriff to identify the family: ${r.cryptoSheriff}`;
    const top = r.families[0];
    const dec = top.decryptor ? `No More Ransom lists a free decryptor for "${top.nmrName}": ${top.decryptor} (it may only work for some versions of the family).` : `No More Ransom lists no free decryptor for this family (list of ${r.generated}); check ${r.cryptoSheriff} for updates.`;
    return `Ransom note of the ${top.family} family (evidence: ${top.evidence.join("; ")}). ${dec}`;
}
