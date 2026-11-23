/**
 * Report export: JSON (machine-readable), CSV (IOCs, one per row) and Markdown (for tickets / case notes).
 */
import crypto from "node:crypto";

export function sha256(bytes) {
    return crypto.createHash("sha256").update(bytes).digest("hex");
}

function iocRows(results) {
    const rows = [];
    const seen = new Set();
    results.forEach((r, i) => {
        for (const f of r.output.findings || []) {
            const k = f.type + "|" + f.value;
            if (seen.has(k)) continue;
            seen.add(k);
            rows.push({ type: f.type, value: f.value, level: f.level, note: f.note || "", result: i + 1, confidence: r.confidence });
        }
    });
    return rows;
}

const csvCell = v => /[",\n\r]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v);

/**
 * @param {{name?:string, bytes:Uint8Array, analysis:object}} p
 * @param {"json"|"csv"|"md"} format
 */
export const REPORT_FORMATS = ["json", "csv", "md", "stix", "misp", "sigma", "yara"];

export function buildReport({ name = "input", bytes, analysis }, format = "json") {
    const meta = { tool: "AutoChef", generated: new Date().toISOString(), input: { name, size: bytes.length, sha256: sha256(bytes) } };
    const results = analysis.results || [];
    const alerts = analysis.alerts || [];
    if (format === "stix") return JSON.stringify(stixBundle(meta, alerts, results), null, 2);
    if (format === "misp") return JSON.stringify(mispEvent(meta, alerts, results, bytes), null, 2);
    if (format === "sigma") return sigmaRule(meta, alerts);
    if (format === "yara") return yaraRule(meta, alerts, results);
    if (format === "json") {
        return JSON.stringify({ ...meta, assessment: analysis.assessment || null, libraryMatches: analysis.libraryMatches || [], stats: analysis.stats,
            results: results.map(r => ({ ...r, output: { ...r.output, base64: undefined } })) }, null, 2);
    }
    if (format === "csv") {
        const rows = iocRows(results);
        return ["alert_level,type,value,note,result_rank,confidence,input_sha256", ...rows.map(r => [r.level, r.type, r.value, r.note, r.result, r.confidence, meta.input.sha256].map(csvCell).join(","))].join("\r\n") + "\r\n";
    }
    // Markdown
    const L = [];
    L.push(`# AutoChef report: ${name}`, "");
    L.push(`- **Generated:** ${meta.generated}`, `- **Size:** ${bytes.length} bytes`, `- **SHA-256:** \`${meta.input.sha256}\``);
    if (analysis.libraryMatches?.length) L.push(`- **Known patterns:** ${analysis.libraryMatches.map(m => `${m.name} ([source](${m.source.url}))`).join("; ")}`);
    L.push("");
    if (analysis.assessment) L.push(`> **Encrypted data:** ${analysis.assessment.message}`, "");
    if (analysis.hash) L.push(`> **Hash:** ${analysis.hash.message}`, "");
    if (analysis.alerts?.length) {
        const s = analysis.alertSummary;
        L.push(`## Alerts: ${s.high} high, ${s.medium} medium, ${s.info} info`, "", "| Level | Type | Value (defanged) | Note |", "|---|---|---|---|");
        for (const a of analysis.alerts) L.push(`| ${a.level} | ${a.type} | \`${defangFinding(a).replace(/\|/g, "\\|")}\` | ${(a.note || "").replace(/\|/g, "\\|")} |`);
        L.push("");
    }
    if (!results.length) L.push(analysis.input?.info?.script ? `The input is already readable ${analysis.input.info.script} text; no hidden layer was found.` : "No convincing decoding was found.");
    results.forEach((r, i) => {
        L.push(`## Result ${i + 1}: ${r.summary} (${r.confidence}, score ${r.score})`, "");
        r.steps.forEach((s, j) => L.push(`${j + 1}. **${s.ops.join(" + ")}**${s.times ? ` ×${s.times}` : ""}: ${s.why}`));
        if (r.loop) L.push("", `_${r.loop}_`);
        L.push("", "Recipe (paste into CyberChef → Load recipe):", "", "```", r.recipeString, "```", "");
        L.push(`[Open in CyberChef](${r.cyberChefUrl.length > 4000 ? r.cyberChefUrl.split("&input=")[0] : r.cyberChefUrl})`, "");
        const fs_ = r.output.findings || [];
        if (fs_.length) L.push("Findings (defanged):", "", ...fs_.slice(0, 60).map(f => `- **${f.type}** (${f.level}): \`${defangFinding(f)}\`${f.note ? " — " + f.note : ""}`), "");
        const prev = r.output.isText ? r.output.preview.slice(0, 1500) : r.output.hexPreview.slice(0, 512);
        L.push("Output preview:", "", "```", prev.replace(/```/g, "ˋˋˋ"), "```", "");
        if (r.output.strings) L.push("Readable strings inside the binary output:", "", "```", r.output.strings.replace(/```/g, "ˋˋˋ"), "```", "");
    });
    return L.join("\n");
}

function defangFinding(f) {
    return f.category === "network" && !/^Email/.test(f.type) ? defang(f.value) : f.type === "Email address" ? f.value.replace("@", "[@]").replace(/\./g, "[.]") : f.value;
}

export function defang(s) {
    return String(s).replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

// ---------- threat-intel exports ----------
const md5 = b => crypto.createHash("md5").update(b).digest("hex");
const sha1 = b => crypto.createHash("sha1").update(b).digest("hex");
const HASH_KIND = { 32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512" };
const stixStr = v => String(v).replace(/\\/g, "\\\\").replace(/'/g, "\\'");

/** STIX 2.1 pattern for a finding, or null when STIX has no observable for it */
function stixPattern(f) {
    const v = stixStr(f.value);
    switch (f.type) {
        case "URL": return `[url:value = '${v}']`;
        case "IPv4 address": return `[ipv4-addr:value = '${v}']`;
        case "IPv6 address": return `[ipv6-addr:value = '${v}']`;
        case "Domain": return `[domain-name:value = '${v}']`;
        case "Email address": return `[email-addr:value = '${v}']`;
        case "Registry path": return `[windows-registry-key:key = '${stixStr(f.value.replace(/^HKLM\\/i, "HKEY_LOCAL_MACHINE\\").replace(/^HKCU\\/i, "HKEY_CURRENT_USER\\").replace(/^HKCR\\/i, "HKEY_CLASSES_ROOT\\").replace(/^HKU\\/i, "HKEY_USERS\\"))}']`;
        case "File name": return `[file:name = '${v}']`;
        case "Process": return `[process:command_line LIKE '%${v}%']`;
        case "User name": return `[user-account:account_login = '${v}']`;
    }
    if (/ hash$/.test(f.type) && HASH_KIND[f.value.length]) return `[file:hashes.'${HASH_KIND[f.value.length]}' = '${f.value.toLowerCase()}']`;
    return null;
}
function stixBundle(meta, alerts, results) {
    const now = meta.generated, id = t => `${t}--${crypto.randomUUID()}`;
    const identity = { type: "identity", spec_version: "2.1", id: id("identity"), created: now, modified: now, name: "AutoChef", identity_class: "system" };
    const objs = [identity];
    const refs = [];
    for (const f of alerts) {
        const pattern = stixPattern(f);
        if (pattern) {
            const o = { type: "indicator", spec_version: "2.1", id: id("indicator"), created: now, modified: now, created_by_ref: identity.id, name: `${f.type}: ${f.value}`.slice(0, 250),
                description: `Found by AutoChef in the decoded output of ${meta.input.name} (SHA-256 ${meta.input.sha256}).${f.note ? " " + f.note + "." : ""}`,
                indicator_types: ["malicious-activity"], pattern, pattern_type: "stix", valid_from: now, labels: [`autochef-${f.level}`] };
            objs.push(o); refs.push(o.id);
        }
    }
    // findings STIX has no observable type for (wallets, phone numbers, countries) and the recipes go in a note
    const other = alerts.filter(f => !stixPattern(f));
    const note = { type: "note", spec_version: "2.1", id: id("note"), created: now, modified: now, created_by_ref: identity.id, abstract: "AutoChef decoding recipes and other findings",
        content: [`Input: ${meta.input.name}, ${meta.input.size} bytes, SHA-256 ${meta.input.sha256}`, "", "Recipes (CyberChef):", ...results.slice(0, 5).map((r, i) => `${i + 1}. [${r.confidence}] ${r.recipeString}`),
            ...(other.length ? ["", "Other findings:", ...other.map(f => `- ${f.type}: ${f.value}${f.note ? " (" + f.note + ")" : ""}`)] : [])].join("\n"),
        object_refs: refs.length ? refs : [identity.id] };
    objs.push(note);
    const sample = { type: "file", spec_version: "2.1", id: id("file"), name: meta.input.name, size: meta.input.size, hashes: { "SHA-256": meta.input.sha256 } };
    objs.push(sample);
    objs.push({ type: "report", spec_version: "2.1", id: id("report"), created: now, modified: now, created_by_ref: identity.id, name: `AutoChef analysis of ${meta.input.name}`,
        report_types: ["indicator", "observed-data"], published: now, object_refs: [sample.id, note.id, ...refs] });
    return { type: "bundle", id: id("bundle"), objects: objs };
}

const MISP_TYPE = {
    "URL": ["url", "Network activity", true], "IPv4 address": ["ip-dst", "Network activity", true], "IPv6 address": ["ip-dst", "Network activity", true],
    "Domain": ["domain", "Network activity", true], "Email address": ["email", "Network activity", true], "Registry path": ["regkey", "Persistence mechanism", true],
    "Windows path": ["filename", "Artifacts dropped", false], "File name": ["filename", "Artifacts dropped", false], "Process": ["filename", "Artifacts dropped", false],
    "User name": ["target-user", "Targeting data", false], "Country": ["text", "Other", false],
};
function mispAttr(f) {
    if (/ hash$/.test(f.type)) { const t = { 32: "md5", 40: "sha1", 64: "sha256", 128: "sha512" }[f.value.length]; if (t) return [t, "Payload delivery", true]; }
    if (f.category === "crypto") return [/^Bitcoin \(/.test(f.type) ? "btc" : /^Monero/.test(f.type) ? "xmr" : /^Dash/.test(f.type) ? "dash" : "text", "Financial fraud", f.type.startsWith("Bitcoin") || f.type.startsWith("Monero")];
    if (f.category === "people" && f.type !== "Country") return ["phone-number", "Person", false];
    return MISP_TYPE[f.type] || ["text", "Other", false];
}
function mispEvent(meta, alerts, results, bytes) {
    const date = meta.generated.slice(0, 10);
    const A = alerts.map(f => { const [type, category, to_ids] = mispAttr(f); return { uuid: crypto.randomUUID(), type, category, value: f.value, to_ids, comment: `AutoChef ${f.level}: ${f.type}${f.note ? " — " + f.note : ""}` }; });
    A.unshift({ uuid: crypto.randomUUID(), type: "sha256", category: "Payload delivery", value: meta.input.sha256, to_ids: true, comment: `Analysed input ${meta.input.name}` },
        { uuid: crypto.randomUUID(), type: "md5", category: "Payload delivery", value: md5(bytes), to_ids: true, comment: `Analysed input ${meta.input.name}` },
        { uuid: crypto.randomUUID(), type: "sha1", category: "Payload delivery", value: sha1(bytes), to_ids: true, comment: `Analysed input ${meta.input.name}` });
    if (results[0]) A.push({ uuid: crypto.randomUUID(), type: "comment", category: "Other", value: `CyberChef recipe (AutoChef, ${results[0].confidence} confidence): ${results[0].recipeString}`, to_ids: false });
    return { Event: { uuid: crypto.randomUUID(), info: `AutoChef analysis: ${meta.input.name}`, date, threat_level_id: alerts.some(a => a.level === "high") ? "2" : "3", analysis: "1", distribution: "0", published: false,
        Tag: [{ name: "tlp:amber" }, { name: "autochef" }], Attribute: A } };
}

const yq = s => `'${String(s).replace(/'/g, "''")}'`;
function sigmaRule(meta, alerts) {
    const net = alerts.filter(f => ["URL", "Domain", "IPv4 address"].includes(f.type)).map(f => f.value).slice(0, 20);
    const procs = alerts.filter(f => f.type === "Process").map(f => f.value).slice(0, 10);
    // Sysmon/EDR write HKU\\<SID>\\… or HKLM\\…: match on the path below the hive
    const reg = [...new Set(alerts.filter(f => f.type === "Registry path").map(f => f.value.replace(/^(Registry::)?(HKEY_[A-Z_]+|HK[A-Z]{1,3}):?(?=\\)/i, "")))].slice(0, 10);
    const L = [`# Generated by AutoChef from ${meta.input.name} (SHA-256 ${meta.input.sha256}) on ${meta.generated}.`, "# A STARTING POINT, not a finished detection: review fields, tune for your log source, and test for false positives.", ""];
    const header = (title, logsource) => [`title: ${yq(title)}`, `id: ${crypto.randomUUID()}`, "status: experimental", `description: ${yq(`Indicators decoded by AutoChef from ${meta.input.name}`)}`,
        "author: AutoChef (generated)", `date: ${meta.generated.slice(0, 10).replace(/-/g, "/")}`, "references:", `  - ${yq("sha256:" + meta.input.sha256)}`, "logsource:", ...logsource, "detection:"];
    const docs = [];
    if (net.length || procs.length) {
        const d = header(`Command line with indicators decoded from ${meta.input.name}`, ["  category: process_creation", "  product: windows"]);
        if (net.length) d.push("  selection_indicators:", "    CommandLine|contains:", ...net.map(v => `      - ${yq(v)}`));
        if (procs.length) d.push("  selection_image:", "    Image|endswith:", ...procs.map(v => `      - ${yq("\\" + v)}`));
        d.push(`  condition: ${net.length && procs.length ? "selection_image and selection_indicators" : net.length ? "selection_indicators" : "selection_image"}`, "falsepositives:", "  - Unknown; review before deployment", "level: high");
        docs.push(d.join("\n"));
    }
    if (reg.length) {
        const d = header(`Registry keys decoded from ${meta.input.name}`, ["  category: registry_set", "  product: windows"]);
        d.push("  selection:", "    TargetObject|contains:", ...reg.map(v => `      - ${yq(v)}`), "  condition: selection", "falsepositives:", "  - Legitimate software writing the same keys", "level: medium");
        docs.push(d.join("\n"));
    }
    if (!docs.length) return L.join("\n") + "# No network, process or registry indicators were found, so there is nothing to build a Sigma rule from.\n";
    return L.join("\n") + docs.join("\n---\n") + "\n";
}

function yaraRule(meta, alerts, results) {
    const pick = alerts.filter(f => ["URL", "Domain", "IPv4 address", "Registry path", "Email address"].includes(f.type) || f.category === "crypto" || (f.type === "File name" && !/^(cmd|powershell|rundll32)\.exe$/i.test(f.value))).map(f => f.value).filter(v => v.length >= 6);
    const uniq = [...new Set(pick)].slice(0, 30);
    const esc = s => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/[^\x20-\x7e]/g, c => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));
    const name = "AutoChef_" + (meta.input.name.replace(/[^A-Za-z0-9_]/g, "_").replace(/^(\d)/, "_$1").slice(0, 40) || "sample") + "_" + meta.input.sha256.slice(0, 8);
    const L = [`// Generated by AutoChef on ${meta.generated}. A STARTING POINT: review and test before use.`, `// The strings were decoded from the sample; they match the DECODED content (memory, dropped files, logs),`, `// not necessarily the obfuscated original.`, "",
        `rule ${name}`, "{", "    meta:", `        description = "Indicators decoded by AutoChef from ${esc(meta.input.name)}"`, `        hash = "${meta.input.sha256}"`, `        date = "${meta.generated.slice(0, 10)}"`, `        recipe = "${esc((results[0]?.recipeString || "").slice(0, 300))}"`];
    if (!uniq.length) return L.concat(["    condition:", "        false // no indicators to match on", "}", ""]).join("\n");
    L.push("    strings:", ...uniq.map((v, i) => `        $s${i} = "${esc(v)}" ascii wide nocase`));
    L.push("    condition:", `        ${uniq.length >= 3 ? "2 of them" : "any of them"}`, "}", "");
    return L.join("\n");
}
