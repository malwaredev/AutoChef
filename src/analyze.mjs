/**
 * Analysis helpers: entropy, printability, file signatures, language hints,
 * IOC extraction and the "how decoded does this look?" score that drives the search.
 */

// ---------- basic byte / text helpers ----------

export function latin1(bytes, max = Infinity) {
    const n = Math.min(bytes.length, max);
    let s = "";
    const CH = 8192;
    for (let i = 0; i < n; i += CH) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(n, i + CH)));
    }
    return s;
}

/** Decode as UTF-8 if valid, otherwise Latin-1. */
export function toText(bytes, max = 200000) {
    const slice = bytes.subarray(0, Math.min(bytes.length, max));
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(slice);
    } catch {
        return latin1(slice);
    }
}

export function entropy(bytes, max = 65536) {
    const n = Math.min(bytes.length, max);
    if (!n) return 0;
    const f = new Uint32Array(256);
    for (let i = 0; i < n; i++) f[bytes[i]]++;
    let e = 0;
    for (let i = 0; i < 256; i++) {
        if (f[i]) {
            const p = f[i] / n;
            e -= p * Math.log2(p);
        }
    }
    return e;
}

/** Fraction of bytes that are printable ASCII / common whitespace (UTF-8 multibyte counted as printable). */
export function printableRatio(bytes, max = 65536) {
    const n = Math.min(bytes.length, max);
    if (!n) return 0;
    // valid UTF-8 (e.g. scripts using emoji / symbols as junk) counts all its multibyte characters as printable
    let utf8 = false;
    try { new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, n)); utf8 = true; } catch { /* cut mid-character or binary */ }
    let ok = 0;
    for (let i = 0; i < n; i++) {
        const b = bytes[i];
        if ((b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13 || b >= 0xc2 || (utf8 && b >= 0x80)) ok++;
    }
    return ok / n;
}

// ---------- file signatures ----------

const SIGNATURES = [
    { name: "Windows PE executable (MZ)", ext: "exe", hex: "4d5a", final: true, check: b => b.length > 64 },
    { name: "ELF executable", ext: "elf", hex: "7f454c46", final: true },
    { name: "PDF document", ext: "pdf", hex: "255044462d", final: true },
    { name: "ZIP archive / Office OpenXML", ext: "zip", hex: "504b0304", final: true },
    { name: "OLE2 / legacy Office document", ext: "doc", hex: "d0cf11e0a1b11ae1", final: true },
    { name: "PNG image", ext: "png", hex: "89504e470d0a1a0a", final: true },
    { name: "JPEG image", ext: "jpg", hex: "ffd8ff(e0|e1|db|ee|e2|fe)", regex: true, final: true, check: b => b.length > 128 },
    { name: "GIF image", ext: "gif", hex: "474946383[79]61", regex: true, final: true },
    { name: "RAR archive", ext: "rar", hex: "526172211a07", final: true },
    { name: "7-Zip archive", ext: "7z", hex: "377abcaf271c", final: true },
    { name: "Java class file", ext: "class", hex: "cafebabe0000", final: true },
    { name: "Mach-O executable", ext: "macho", hex: "cffaedfe0[7c]000001", regex: true, final: true },
    { name: "Windows shortcut (LNK)", ext: "lnk", hex: "4c00000001140200", final: true },
    { name: "RTF document", ext: "rtf", hex: "7b5c72746631", final: true },
    { name: "Microsoft Cabinet", ext: "cab", hex: "4d534346", final: true },
    // compressed containers: intermediate, AutoChef should decompress them
    { name: "Gzip compressed data", ext: "gz", hex: "1f8b", final: false },
    { name: "Bzip2 compressed data", ext: "bz2", hex: "425a68", final: false },
    { name: "Zlib compressed data", ext: "zlib", hex: "78(01|5e|9c|da)", final: false, regex: true },
    { name: "LZMA compressed data", ext: "lzma", hex: "5d0000", final: false },
    { name: "LZ4 frame", ext: "lz4", hex: "04224d18", final: false },
];

export function detectFileType(bytes) {
    const head = hexOf(bytes, 0, 16);
    for (const s of SIGNATURES) {
        const ok = s.regex ? new RegExp("^" + s.hex).test(head) : head.startsWith(s.hex);
        if (ok && (!s.check || s.check(bytes))) {
            if (s.ext === "exe" && !isLikelyPE(bytes)) continue;
            return s;
        }
    }
    return null;
}

function isLikelyPE(b) {
    if (b.length < 0x40) return false;
    const off = b[0x3c] | (b[0x3d] << 8) | (b[0x3e] << 16) | (b[0x3f] << 24);
    if (off > 0 && off + 4 <= b.length && b[off] === 0x50 && b[off + 1] === 0x45 && b[off + 2] === 0 && b[off + 3] === 0) return true;
    return latin1(b, 512).includes("This program");
}

export function hexOf(bytes, start = 0, len = 16) {
    let s = "";
    for (let i = start; i < Math.min(bytes.length, start + len); i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
}

/** UTF-16LE/BE text: printable byte every other position, 00 in between. */
export function isUtf16Text(bytes) {
    const n = Math.min(bytes.length, 4000);
    if (n < 8) return false;
    let le = 0, be = 0;
    for (let i = 0; i + 1 < n; i += 2) {
        const a = bytes[i], b = bytes[i + 1];
        const pa = (a >= 0x20 && a < 0x7f) || a === 9 || a === 10 || a === 13;
        const pb = (b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13;
        if (pa && b === 0) le++;
        if (pb && a === 0) be++;
    }
    const pairs = Math.floor(n / 2);
    return le / pairs > 0.85 || be / pairs > 0.85;
}

/** Printable ASCII runs (length >= min) inside binary data, joined by newlines. */
export function binaryStrings(bytes, min = 6, max = 262144) {
    const n = Math.min(bytes.length, max);
    const runs = [];
    let start = -1, covered = 0;
    for (let i = 0; i <= n; i++) {
        const b = i < n ? bytes[i] : 0;
        const pr = b >= 32 && b < 127;
        if (pr && start < 0) start = i;
        if (!pr && start >= 0) {
            if (i - start >= min) { runs.push(latin1(bytes.subarray(start, i))); covered += i - start; }
            start = -1;
        }
    }
    return { text: runs.join("\n"), coverage: n ? covered / n : 0 };
}

// ---------- IOC extraction ----------

const TLD = "com|net|org|info|biz|io|ru|cn|xyz|top|online|site|club|co|uk|de|in|us|me|tk|ml|ga|cf|gq|pw|cc|su|onion|ws|link|live|app|dev|shop|icu|vip|work|tech";

export function extractIOCs(text) {
    const uniq = a => [...new Set(a)].slice(0, 50);
    const urls = uniq(text.match(/\b(?:https?|ftp|hxxps?):\/\/[A-Za-z0-9\[][^\s"'<>`)\]}]*/gi) || []);
    const ips = uniq((text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || [])
        .filter(ip => !/^(0\.|255\.255|1\.0\.0|2\.0\.0)/.test(ip)));
    // domains: one consistent case (random mixed-case garbage like "gA.mAc" is not a domain)
    const domains = uniq((text.match(new RegExp(`\\b(?:[a-z0-9-]{2,63}\\.)+(?:${TLD})\\b|\\b(?:[A-Z0-9-]{2,63}\\.)+(?:${TLD.toUpperCase()})\\b`, "g")) || [])
        .filter(d => !/^(system|microsoft\.powershell|this|document|window)\./i.test(d) && /[a-z]{3,}|[A-Z]{3,}/.test(d.split(".")[0])));
    const emails = uniq(text.match(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g) || []);
    const files = uniq(text.match(/\b[\w-]+\.(?:exe|dll|ps1|vbs|js|hta|bat|cmd|scr|lnk|jar|zip|docm|xlsm)\b/gi) || []);
    const registry = uniq(text.match(/\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s"']+/g) || []);
    return { urls, ips, domains, emails, files, registry };
}

export function iocCount(iocs) {
    return Object.values(iocs).reduce((a, v) => a + v.length, 0);
}

// ---------- language / word scoring ----------

const WORDS = new Set((
    // common English
    "the and for are but not you all any can her was one our out day get has him his how man new now old see two way who boy did its let put say she too use that with have this will your from they know want been good much some time very when come here just like long make many more only over such take than them well were what into year also back after first other could would there their which about these then think where because through"
    + " hello world password secret flag message welcome test data user admin login error success true false null none key value"
    // code & scripting
    + " function return var let const new object string array char byte int void public private static class import from print echo else elif while break case switch catch try throw document window eval write script http https www html body head div src type text application json xml"
    // malware / windows / powershell keywords
    // command-line / sysadmin vocabulary (Windows, Linux, macOS) seen in attacker tooling
    + " netsh advfirewall firewall rule profile state off allow block add delete query reg regedit value data force type dword sz net user group localgroup administrators domain share use view sc config start stop service services wmic process call create get caption executablepath commandline whoami ipconfig systeminfo tasklist taskkill findstr dir copy move del type attrib icacls takeown vssadmin shadows bcdedit wevtutil cipher format esentutl certreq nltest dsquery adfind klist mimikatz sekurlsa logonpasswords lsass procdump comsvcs minidump rundll32 msiexec installutil regasm regsvcs msbuild cmstp forfiles pcalua odbcconf ftp tftp telnet ssh scp sftp nc ncat netcat socat python python3 perl ruby php node java javac sudo su chown chmod chattr crontab cron systemctl journalctl service kill pkill ps top grep egrep awk sed cut sort uniq head tail find xargs tar gzip gunzip zip unzip base64 openssl echo cat touch rm rmdir mkdir cp mv ln ls pwd cd export env history unset alias id uname hostname ifconfig ip route arp netstat ss iptables ufw useradd usermod userdel passwd shadow etc var opt usr home root dev null proc tmp launchctl defaults osascript plutil security keychain dscl spctl csrutil sqlite3 file path name list show set get new remove out content item property child test write host output null true false file folder directory registry key"
    + " powershell invoke expression iex system convert frombase64string download downloadstring downloadfile webclient net invoke-webrequest start-process hidden bypass encodedcommand noprofile windowstyle executionpolicy cmd exe dll rundll32 regsvr32 mshta wscript cscript shell createobject activexobject run temp appdata programdata startup registry hklm hkcu software microsoft windows currentversion runonce payload stage shellcode virtualalloc createthread memory stream compression deflatestream gzipstream readtoend encoding unicode utf8 ascii getstring bytes reflection assembly load invoke entrypoint certutil bitsadmin schtasks curl wget chmod bash bin tmp sleep socket connect send recv beacon user-agent mozilla"
).split(/\s+/));

const BIGRAMS = new Set("th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur".split(" "));

/** 0..1: how much of the letter content is made of known words + common bigrams. */
export function languageScore(text) {
    const sample = text.slice(0, 20000);
    const tokens = sample.match(/[A-Za-z][A-Za-z-]{1,}/g) || [];
    let letters = 0, known = 0;
    for (const t of tokens) {
        letters += t.length;
        const lower = t.toLowerCase();
        if (WORDS.has(lower)) known += t.length;
        else {
            // camelCase / PascalCase splitting: FromBase64String -> from base64 string
            const parts = t.split(/(?=[A-Z])|-/).map(p => p.toLowerCase()).filter(p => p.length > 2);
            const hit = parts.filter(p => WORDS.has(p)).reduce((a, p) => a + p.length, 0);
            known += hit * 0.8;
        }
    }
    const wordCover = letters ? known / letters : 0;

    const lower = sample.toLowerCase().replace(/[^a-z]/g, "");
    let bg = 0;
    for (let i = 0; i < lower.length - 1; i++) if (BIGRAMS.has(lower.substr(i, 2))) bg++;
    const bigramRatio = lower.length > 1 ? bg / (lower.length - 1) : 0; // English text ~0.35-0.45, random ~0.07

    // spaces / punctuation look like natural text or code
    const spaces = (sample.match(/[\s]/g) || []).length / Math.max(1, sample.length);
    const spaceScore = spaces > 0.03 && spaces < 0.35 ? 1 : spaces > 0 ? 0.4 : 0;

    // inverted case ("sET-eXECUTIONpOLICY", typical of XOR 0x20) is not natural text
    const inverted = tokens.filter(t => /^[a-z][A-Z]{2,}/.test(t)).length / Math.max(1, tokens.length);
    return Math.max(0, Math.min(1, 0.55 * wordCover + 0.3 * Math.min(1, bigramRatio / 0.3) + 0.15 * spaceScore - 0.5 * inverted));
}

/** Recognise what kind of plaintext this is (for explanations). */
export function guessLanguage(text) {
    const t = text.slice(0, 20000);
    if (/\b(Invoke-Expression|IEX|New-Object|FromBase64String|\$env:|Start-Process|-ExecutionPolicy|\[System\.)/i.test(t)) return "PowerShell";
    if (/\b(CreateObject|WScript\.|Dim |Sub |End Sub|Chr\()/i.test(t)) return "VBScript / VBA";
    if (/\b(function\s*\(|var |let |const |document\.|window\.|eval\(|=>)/.test(t)) return "JavaScript";
    if (/^\s*<(!doctype|html|script|\?xml)/i.test(t)) return "HTML / XML";
    if (/^\s*[{[][\s\S]*[}\]]\s*$/.test(t.trim()) && /"\s*:/.test(t)) return "JSON";
    if (/(^|\n)\s*(cmd(\.exe)?\s*\/c|@echo off|set \w+=)/i.test(t)) return "Batch / cmd";
    if (/#!\/bin\/(ba)?sh|\b(wget|curl|chmod \+x)\b/.test(t)) return "Shell script";
    return null;
}

// ---------- "still encoded?" detection ----------

export function looksEncoded(text) {
    const s = text.trim();
    if (s.length < 8) return null;
    const ns = s.replace(/\s+/g, "");
    if (/^[01]+$/.test(ns) && ns.length % 8 === 0) return "binary";
    if (/^(0x)?[0-9a-f]+$/i.test(ns) && ns.length % 2 === 0) return "hex";
    if (/^([0-9a-f]{2}[\s:,-]?)+$/i.test(s) && ns.length % 2 === 0 && /[\s:,-]/.test(s)) return "hex";
    if (/^(\\x[0-9a-f]{2})+$/i.test(ns) || /^(0x[0-9a-f]{2},?)+$/i.test(ns)) return "hex";
    if (/^\d{1,3}([\s,;]+\d{1,3}){3,}$/.test(s)) return "decimal";
    // Base64/Base32 can be wrapped across lines but never has spaces between words
    const spaced = / \S/.test(s);
    if (!spaced && /^[A-Z2-7]+=*$/.test(ns) && ns.length >= 16 && (ns.length % 8 === 0 || /=$/.test(ns))) return "base32";
    if (!spaced && /^[A-Za-z0-9+/]+={0,2}$/.test(ns) && ns.length >= 12 && /[0-9+/=]|[a-z][A-Z]/.test(ns)) return "base64";
    if (!spaced && /^[A-Za-z0-9_-]+={0,2}$/.test(ns) && ns.length >= 16 && /[-_]/.test(ns) && /\d/.test(ns) && !/[a-z]{3,}-[A-Z][a-z]+/.test(ns)) return "base64url";
    if (/^[.\-\/ ]+$/.test(s) && /\./.test(s) && /-/.test(s)) return "morse";
    if ((s.match(/%[0-9a-f]{2}/gi) || []).length > s.length / 6) return "url";
    return null;
}

/**
 * Text that is readable but still hides content (embedded blobs, char-code
 * arrays, escape soup) is penalised so the search keeps digging.
 */
export function obfuscation(text) {
    const t = text.slice(0, 200000);
    const len = Math.max(1, t.length);
    const reasons = [];
    let penalty = 0;
    const cover = (re) => (t.match(re) || []).reduce((a, m) => a + m.length, 0) / len;

    const b64 = cover(/[A-Za-z0-9+/]{40,}={0,2}/g);
    if (b64 > 0.15) { penalty += 45 * b64; reasons.push("embedded Base64 blob"); }
    // code that explicitly decodes an embedded blob is a loader, not the payload
    if (/frombase64string|atob\s*\(|base64_decode|decodebase64|base64decode|convert\.frombase64/i.test(t) && /[A-Za-z0-9+/]{100,}={0,2}/.test(t)) { penalty += 18; reasons.push("loader that decodes an embedded blob"); }
    if (/gzinflate|gzuncompress|str_rot13|eval\s*\(\s*(gzinflate|base64_decode|str_rot13)/i.test(t) && /[A-Za-z0-9+/]{60,}={0,2}/.test(t)) { penalty += 12; reasons.push("PHP decoder chain"); }
    const hx = cover(/(?:[0-9a-fA-F]{2}){24,}/g);
    if (hx > 0.15) { penalty += 45 * hx; reasons.push("embedded hex blob"); }
    const arr = cover(/(?:-?\d{1,3}\s*,\s*){15,}-?\d{1,3}/g);
    if (arr > 0.15) { penalty += 50 * arr; reasons.push("byte/char-code arrays"); }
    const cc = (t.match(/\[char\]\s*\d{2,3}|chrw?\(\s*\d{2,3}|fromcharcode\(/gi) || []).length;
    if (cc >= 5) { penalty += Math.min(40, cc); reasons.push("character-code obfuscation"); }
    const esc = cover(/(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%u[0-9a-f]{4}|%[0-9a-f]{2}|&#x?[0-9a-f]+;)+/gi);
    if (esc > 0.2) { penalty += 40 * esc; reasons.push("escape sequences"); }
    const concat = (t.match(/['"]\s*\+\s*['"]/g) || []).length;
    if (concat >= 4) { penalty += Math.min(15, concat); reasons.push("string concatenation"); }
    const carets = (t.match(/\^[a-zA-Z]/g) || []).length;
    if (carets >= 4) { penalty += Math.min(25, carets); reasons.push("caret obfuscation"); }
    const ticks = (t.match(/`[a-zA-Z]/g) || []).length;
    if (ticks >= 4) { penalty += Math.min(12, ticks); reasons.push("backtick obfuscation"); }
    return { penalty, reasons };
}

// ---------- the main score ----------

/**
 * Score 0..100: how much does this look like a final, useful result?
 * Returns details used for explanations and ranking.
 */
/**
 * Code-point offset check ("each character = one byte + a fixed offset", e.g. U+4E00 + byte).
 * Returns the decoded bytes and offset when every character lies in one 256-code-point window AND
 * the decoded bytes are convincing (a known file, or clean text in English or a strict encoding).
 * Natural Thai or kana text also fits in one window, but its "decoded" bytes are noise, so it fails here.
 */
export function codePointDecodes(text) {
    if (text.length < 8 || text.charCodeAt(0) < 0x100) return null; // every character must be >= U+0100
    const s = text.replace(/\s+$/, "");
    if (s.length < 8 || s.includes("\uFFFD")) return null;
    const cps = Array.from(s, c => c.codePointAt(0));
    if (cps.length < 8 || cps.some(c => c < 0x100)) return null;
    let lo = Infinity, hi = -Infinity;
    for (const c of cps) { if (c < lo) lo = c; if (c > hi) hi = c; }
    if (hi - lo > 255) return null;
    const sample = cps.length > 4096 ? cps.slice(0, 4096) : cps;
    let best = null;
    for (let base = Math.max(0, hi - 255); base <= lo; base++) {
        const out = Buffer.from(sample.map(c => c - base));
        const ft = detectFileType(out);
        let sc = 0;
        if (ft) sc = ft.final ? 3 : 2;
        else if (printableRatio(out) >= 0.97) {
            const t = latin1(out);
            const clean = (t.match(/[A-Za-z0-9 \t\r\n.,:;_\-'"=()\/\\|$+]/g) || []).length / t.length;
            sc = clean < 0.85 ? 0 : looksEncoded(t) ? 1.5 : languageScore(t) >= 0.35 ? 1 + languageScore(t) : 0;
        }
        if (sc > (best?.sc || 0)) best = { base, sc };
    }
    return best ? { base: best.base, bytes: Buffer.from(cps.map(c => c - best.base)) } : null;
}

/** Natural text in a non-Latin script (Thai, Japanese, Chinese, Korean, Cyrillic, Arabic, …): readable as it is. */
const SCRIPTS = ["Han", "Hiragana", "Katakana", "Hangul", "Thai", "Cyrillic", "Arabic", "Hebrew", "Greek", "Devanagari", "Bengali", "Tamil", "Telugu", "Gujarati", "Gurmukhi", "Kannada", "Malayalam", "Sinhala", "Lao", "Khmer", "Myanmar", "Georgian", "Armenian", "Ethiopic"];
const SCRIPT_RE = SCRIPTS.map(n => [n, new RegExp(`\\p{Script=${n}}`, "u")]);
export function nonLatinScript(text) {
    // cheap pre-check: at least a third of the UTF-16 units must be outside Latin (most outputs stop here)
    let hiUnits = 0;
    const n0 = Math.min(text.length, 20000);
    for (let i = 0; i < n0; i++) if (text.charCodeAt(i) > 0x24f) hiUnits++;
    if (hiUnits < n0 / 3) return null;
    const chars = Array.from(text.slice(0, 20000));
    if (chars.length < 4) return null;
    let nl = 0, bad = 0;
    const counts = new Map();
    for (const c of chars) {
        if (/[\p{L}\p{M}]/u.test(c) && c.codePointAt(0) > 0x24f) {
            nl++;
            for (const [n, re] of SCRIPT_RE) if (re.test(c)) { counts.set(n, (counts.get(n) || 0) + 1); break; }
        } else if (!/[\p{L}\p{N}\p{P}\p{Zs}\s]/u.test(c)) bad++;
    }
    if (nl < chars.length * 0.5 || bad > chars.length * 0.05) return null;
    if (codePointDecodes(text)) return null; // looks like letters, but is a byte encoding
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
    if (!top || top[1] < nl * 0.6) return null;
    return { Han: "Chinese/Japanese (Han)", Hiragana: "Japanese", Katakana: "Japanese" }[top[0]] || top[0];
}

export function scoreOutput(bytes) {
    const info = { size: bytes.length };
    if (!bytes.length) return { score: 0, info };

    const ft = detectFileType(bytes);
    info.entropy = +entropy(bytes).toFixed(3);
    info.printable = +printableRatio(bytes).toFixed(3);
    if (ft) info.fileType = ft.name;

    if (ft && ft.final) {
        info.kind = "file";
        return { score: 88 + Math.min(7, bytes.length / 4096), info };
    }
    if (ft && !ft.final) {
        info.kind = "compressed";
        return { score: 30, info };
    }

    if (info.printable < 0.85 && isUtf16Text(bytes)) {
        info.kind = "encoded-text";          // readable once decoded as UTF-16: keep digging
        info.encoding = "utf-16";
        return { score: 25, info };
    }
    if (info.printable < 0.85) {
        info.kind = "binary";
        // binary with meaningful embedded strings (shellcode config, C2, user agents) is interesting
        const st = binaryStrings(bytes);
        let score = Math.max(2, 25 * info.printable - (info.entropy > 7.2 ? 10 : 0));
        if (st.text.length >= 12) {
            const iocs = extractIOCs(st.text);
            const n = iocCount(iocs);
            const lang = languageScore(st.text);
            if (n) info.iocs = iocs;
            info.strings = st.text.slice(0, 400);
            score = Math.max(score, 10 + 40 * lang + Math.min(30, n * 10));
        }
        return { score: Math.min(80, score), info };
    }

    const text = toText(bytes);
    const enc = looksEncoded(text);
    const lang = languageScore(text);
    const iocs = extractIOCs(text);
    const nIoc = iocCount(iocs);
    const plang = guessLanguage(text);
    const script = !enc && lang < 0.6 ? nonLatinScript(text) : null;
    if (script) { info.script = script; }
    info.kind = enc ? "encoded-text" : "text";
    if (enc) info.encoding = enc;
    if (plang) info.language = plang;
    info.languageScore = +lang.toFixed(3);
    info.iocs = iocs;

    const obf = obfuscation(text);
    if (obf.reasons.length) info.obfuscation = obf.reasons;

    let score = 20 + 55 * (script ? Math.max(lang, 0.6) : lang); // natural non-Latin text is already readable
    score += Math.min(15, nIoc * 4);
    if (plang) score += 8;
    if (enc) score -= 30;                  // still encoded: intermediate, not the answer
    score -= obf.penalty;                  // readable wrapper around still-hidden content
    if (text.length < 4) score -= 15;
    score += 7 * (info.printable - 0.85) / 0.15;
    return { score: Math.max(1, Math.min(99, score)), info };
}
