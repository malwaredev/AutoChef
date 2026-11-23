/**
 * Readable view of decoded scripts: undoes the cosmetic obfuscation that is left after decoding
 * (string splitting, format operators, char codes, backticks, random case, random names).
 *
 * This is a display aid, not a CyberChef operation, and it never executes the script: every
 * rewrite is a text transformation of constant expressions only.
 */
import { minify } from "terser";

const PS_CMDLETS = ["Add-Type", "ConvertFrom-Base64", "ConvertTo-SecureString", "Copy-Item", "ForEach-Object", "Get-Content", "Get-Item", "Get-ItemProperty", "Get-Process", "Get-Variable", "Get-WmiObject", "Import-Module", "Invoke-Command", "Invoke-Expression", "Invoke-RestMethod", "Invoke-WebRequest", "Join-Path", "New-Item", "New-ItemProperty", "New-Object", "Out-File", "Out-Null", "Remove-Item", "Set-Content", "Set-Item", "Set-ItemProperty", "Set-Variable", "Start-BitsTransfer", "Start-Process", "Start-Sleep", "Stop-Process", "Where-Object", "Write-Host", "Write-Output", "Test-Path", "Get-ChildItem", "Expand-Archive", "Register-ScheduledTask", "New-ScheduledTaskAction"];
const PS_TYPES = ["System.IO.Directory", "System.IO.File", "System.IO.MemoryStream", "System.IO.Compression.DeflateStream", "System.IO.Compression.GzipStream", "System.IO.Compression.CompressionMode", "System.IO.StreamReader", "System.Net.WebClient", "System.Net.ServicePointManager", "System.Net.SecurityProtocolType", "System.Text.Encoding", "System.Convert", "System.Reflection.Assembly", "System.Diagnostics.Process", "System.Runtime.InteropServices.Marshal", "Net.WebClient", "IO.File", "IO.Directory"];
const canon = new Map([...PS_CMDLETS, ...PS_TYPES, "Variable", "DownloadString", "DownloadFile", "DownloadData", "FromBase64String", "GetString", "UTF8", "Unicode", "ASCII", "ReadToEnd", "Invoke", "Load", "EntryPoint", "CreateDirectory", "WriteAllBytes", "ReadAllBytes"].map(w => [w.toLowerCase(), w]));

const q = s => "'" + s.replace(/'/g, "''") + "'";
function psUnquote(lit) {
    if (lit[0] === "'") return lit.slice(1, -1).replace(/''/g, "'");
    return lit.slice(1, -1).replace(/`(.)/g, (m, c) => ({ n: "\n", t: "\t", r: "\r", 0: "\0", a: "\x07" }[c] ?? c));
}
const PS_STR = String.raw`'(?:[^']|'')*'|"(?:[^"\`$]|\`.)*"`;

export function cleanPowerShell(src) {
    let s = src;
    // backticks inside words (n`e`w-o`bje`ct) – keep real escapes like `n `t
    // outside double-quoted strings a backtick only escapes the next character, so `o`b`j is just "obj"
    s = s.split(/("(?:[^"`]|`.)*")/).map((part, i) => i % 2 ? part : part.replace(/(\w)`(\w)/g, "$1$2").replace(/(\w)`(\w)/g, "$1$2")).join("");
    for (let pass = 0; pass < 6; pass++) {
        const before = s;
        // "{1}{0}" -f 'a','b'
        s = s.replace(new RegExp(String.raw`\(?\s*(${PS_STR})\s*-f\s*((?:${PS_STR})(?:\s*,\s*(?:${PS_STR}))*)\s*\)?`, "gi"), (m, fmt, args) => {
            const list = [...args.matchAll(new RegExp(PS_STR, "g"))].map(x => psUnquote(x[0]));
            const f = psUnquote(fmt);
            if (!/\{\d+\}/.test(f)) return m;
            const out = f.replace(/\{(\d+)\}/g, (mm, i) => list[+i] ?? mm);
            return q(out);
        });
        // 'ab' + 'cd'
        s = s.replace(new RegExp(String.raw`(${PS_STR})\s*\+\s*(${PS_STR})`, "g"), (m, a, b) => q(psUnquote(a) + psUnquote(b)));
        // [char]72 , [char]0x48
        s = s.replace(/\[char\]\s*\(?\s*(0x[0-9a-f]+|\d+)\s*\)?/gi, (m, n) => { const c = parseInt(n); return c >= 32 && c < 127 ? q(String.fromCharCode(c)) : m; });
        // ('a','b','c') -join ''   and   -join ('a','b')
        s = s.replace(new RegExp(String.raw`\(\s*((?:${PS_STR})(?:\s*,\s*(?:${PS_STR}))+)\s*\)\s*-join\s*(${PS_STR})`, "gi"), (m, list, sep) => q([...list.matchAll(new RegExp(PS_STR, "g"))].map(x => psUnquote(x[0])).join(psUnquote(sep))));
        // ('abc') -> 'abc'
        s = s.replace(new RegExp(String.raw`(?<![\w\]])\(\s*(${PS_STR})\s*\)`, "g"), "$1");
        if (s === before) break;
    }
    // canonical case for known cmdlets / .NET names (sEt-iTeM -> Set-Item)
    s = s.replace(/\b[A-Za-z]+(?:[-.][A-Za-z]+)*\b/g, w => canon.get(w.toLowerCase()) || w);
    // a statement per line
    s = s.replace(/;\s*(?=\S)/g, ";\n");
    return renameRandom(s, /\$([A-Za-z_][A-Za-z0-9_]*)/g, n => "$" + n, "var");
}

export function cleanVBA(src) {
    let s = src;
    for (let pass = 0; pass < 6; pass++) {
        const before = s;
        s = s.replace(/\bChrW?\$?\(\s*(\d{1,5})\s*\)/gi, (m, n) => +n >= 32 && +n < 127 ? `"${String.fromCharCode(+n).replace(/"/g, '""')}"` : m);
        s = s.replace(/"((?:[^"]|"")*)"\s*[&+]\s*"((?:[^"]|"")*)"/g, '"$1$2"');
        if (s === before) break;
    }
    return s;
}

export async function cleanJavaScript(src) {
    try {
        const r = await minify(src, { compress: { evaluate: true, unsafe: false, passes: 2, dead_code: false, unused: false, side_effects: false, sequences: false, conditionals: false, join_vars: false, collapse_vars: false, reduce_vars: true, inline: false }, mangle: false, format: { beautify: true, comments: true, ascii_only: false } });
        if (!r.code) return null;
        return renameRandom(r.code, /\b(_0x[0-9a-f]{3,}|_?[a-zA-Z]{1,2}\d{3,}[a-zA-Z0-9]*)\b/g, n => n, "v");
    } catch { return null; }
}

/** Rename identifiers that look machine-generated (_0x4f2a, wgN9, kZq83HdX) to var1, var2 … */
function renameRandom(s, re, wrap, prefix) {
    const names = new Map();
    let i = 0;
    const randomish = n => /^_0x[0-9a-f]+$/i.test(n) || (n.length >= 4 && n.length <= 24 && /\d/.test(n) && /[a-z]/.test(n) && /[A-Z]/.test(n)) || (n.length >= 8 && !/[aeiou]{1}/i.test(n.replace(/\d/g, "")));
    for (const m of s.matchAll(re)) {
        const n = m[1];
        if (/^(env|true|false|null|_|args|input|this|PSHOME|PSVersionTable|ExecutionContext|ShellId|host|pwd|home)$/i.test(n)) continue;
        if (randomish(n) && !names.has(n)) names.set(n, `${prefix}${++i}`);
    }
    if (!names.size) return s;
    return s.replace(re, (m, n) => names.has(n) ? m.replace(n, names.get(n)) : m);
}

/** Readable view for a decoded output, or null when there is nothing to improve */
export async function readableView(text, language) {
    if (!text || text.length > 300000) return null;
    let out = null;
    if (language === "PowerShell" || /\b(?:iex|invoke-expression|new-object|set-item|-f\s*'|\[char\])/i.test(text) && /[$]\w/.test(text)) out = cleanPowerShell(text);
    else if (language === "VBScript / VBA" || /\b(Chr\(|Sub |Function |Dim )/.test(text)) out = cleanVBA(text);
    else if (language === "JavaScript") out = await cleanJavaScript(text);
    if (!out || out.trim() === text.trim()) return null;
    return out;
}
