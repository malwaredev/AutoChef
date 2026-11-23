/**
 * Findings: indicators and artefacts found in decoded output, with an alert level.
 *
 *   network     URLs, IPv4/IPv6 addresses, domains, e-mail addresses
 *   crypto      cryptocurrency addresses (checksums verified where the format has one)
 *   hashes      MD5 / SHA-1 / SHA-256 / SHA-512 values
 *   host        Windows paths, UNC paths, registry paths, file names, process names, user names
 *   people      phone numbers (fixed line / mobile, with country), country names
 *
 * Phone numbers are parsed and validated with libphonenumber-js (Google's libphonenumber metadata).
 * Country names come from the ICU data built into Node.js (Intl.DisplayNames), not a hand-made list.
 * Cryptocurrency formats follow the coins' own specifications: Base58Check (Bitcoin wiki),
 * BIP-173/BIP-350 (Bech32/Bech32m), EIP-55, Stellar StrKey (SEP-23), Monero and Ripple address docs.
 */
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { extractIOCs } from "./analyze.mjs";
import { pluginFindings } from "./plugins.mjs";
import { keccak_256 } from "@noble/hashes/sha3.js";

const require = createRequire(import.meta.url);
let phoneLib = null;
try { phoneLib = require("libphonenumber-js/max"); } catch { /* optional: run `npm run setup` */ }

// ---------- encodings used by addresses ----------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const XRP58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
function b58decode(s, alpha = B58) {
    let n = 0n;
    for (const c of s) { const i = alpha.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); }
    const bytes = [];
    while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
    for (const c of s) { if (c === alpha[0]) bytes.unshift(0); else break; }
    return Buffer.from(bytes);
}
const sha256d = b => crypto.createHash("sha256").update(crypto.createHash("sha256").update(b).digest()).digest();
/** Base58Check: payload + 4-byte double-SHA-256 checksum */
function b58check(s, alpha = B58) {
    const b = b58decode(s, alpha);
    if (!b || b.length < 5) return null;
    const p = b.subarray(0, -4);
    return sha256d(p).subarray(0, 4).equals(b.subarray(-4)) ? p : null;
}
// BIP-173 / BIP-350
const BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Polymod(values) {
    const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) { const top = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= G[i]; }
    return chk >>> 0;
}
function bech32Valid(addr) {
    const s = addr.toLowerCase();
    if (addr !== s && addr !== addr.toUpperCase()) return false;
    const pos = s.lastIndexOf("1");
    if (pos < 1 || pos + 7 > s.length) return false;
    const hrp = s.slice(0, pos), data = [...s.slice(pos + 1)].map(c => BECH.indexOf(c));
    if (data.some(x => x < 0)) return false;
    const exp = [...hrp].map(c => c.charCodeAt(0) >> 5).concat([0], [...hrp].map(c => c.charCodeAt(0) & 31));
    const pm = bech32Polymod(exp.concat(data));
    return pm === 1 || pm === 0x2bc830a3; // Bech32 / Bech32m
}
// Stellar StrKey: base32, version byte, CRC16-XModem
function crc16x(b) { let c = 0; for (const x of b) { c ^= x << 8; for (let i = 0; i < 8; i++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) & 0xffff : (c << 1) & 0xffff; } return c; }
function stellarValid(s) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0, val = 0; const out = [];
    for (const c of s) { const i = A.indexOf(c); if (i < 0) return false; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
    const b = Buffer.from(out);
    if (b.length !== 35) return false;
    const crc = crc16x(b.subarray(0, 33));
    return b[33] === (crc & 255) && b[34] === (crc >> 8);
}

/** EIP-55: mixed-case addresses carry a Keccak-256 checksum; all-lower/upper ones carry none */
function eip55(addr) {
    const h = addr.slice(2);
    if (h === h.toLowerCase() || h === h.toUpperCase()) return null; // no checksum to verify
    const hash = Buffer.from(keccak_256(Buffer.from(h.toLowerCase(), "ascii"))).toString("hex");
    for (let i = 0; i < 40; i++) {
        const c = h[i];
        if (/[a-f]/i.test(c) && ((parseInt(hash[i], 16) >= 8) !== (c === c.toUpperCase()))) return false;
    }
    return true;
}
/** Monero Base58 (8-byte blocks of 11 characters) + Keccak-256 checksum; returns the network byte or null */
function moneroCheck(addr) {
    const SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    const out = [];
    for (let i = 0; i < addr.length; i += 11) {
        const blk = addr.slice(i, i + 11), nbytes = SIZES.indexOf(blk.length);
        if (nbytes < 0) return null;
        let n = 0n;
        for (const c of blk) { const d = B58.indexOf(c); if (d < 0) return null; n = n * 58n + BigInt(d); }
        if (n >> BigInt(8 * nbytes)) return null;
        for (let k = nbytes - 1; k >= 0; k--) out.push(Number((n >> BigInt(8 * k)) & 255n));
    }
    const b = Buffer.from(out);
    if (b.length < 5) return null;
    const sum = Buffer.from(keccak_256(b.subarray(0, -4))).subarray(0, 4);
    return sum.equals(b.subarray(-4)) ? b[0] : null;
}

/** Bitcoin Cash CashAddr checksum (BCH code, spec: github.com/bitcoincashorg/bitcoincash.org, cashaddr.md) */
function cashAddrValid(addr) {
    const full = addr.toLowerCase().includes(":") ? addr.toLowerCase() : "bitcoincash:" + addr.toLowerCase();
    const [prefix, payload] = full.split(":");
    const G = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
    let c = 1n;
    const vals = [...[...prefix].map(ch => ch.charCodeAt(0) & 31), 0, ...[...payload].map(ch => BECH.indexOf(ch))];
    if (vals.some(v => v < 0)) return false;
    for (const d of vals) {
        const c0 = c >> 35n;
        c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
        for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= G[i];
    }
    return (c ^ 1n) === 0n;
}

/** [{coin, address, checked}] */
export function cryptoAddresses(text) {
    const out = [], seen = new Set();
    const add = (coin, address, checked) => { if (!seen.has(address)) { seen.add(address); out.push({ coin, address, checked }); } };
    // Base58Check families: version byte → coin
    const VERSIONS = [
        [0x00, "Bitcoin (P2PKH)"], [0x05, "Bitcoin (P2SH)"], [0x6f, "Bitcoin testnet"], [0xc4, "Bitcoin testnet (P2SH)"],
        [0x30, "Litecoin"], [0x32, "Litecoin (P2SH)"], [0x1e, "Dogecoin"], [0x16, "Dogecoin (P2SH)"],
        [0x4c, "Dash"], [0x10, "Dash (P2SH)"], [0x41, "TRON"], [0x17, "Ravencoin"],
    ];
    for (const m of text.matchAll(/\b[1-9A-HJ-NP-Za-km-z]{25,35}\b/g)) {
        const p = b58check(m[0]);
        if (!p) continue;
        if (p.length === 21) { const v = VERSIONS.find(x => x[0] === p[0]); if (v) add(v[1], m[0], true); }
        else if (p.length === 22 && p[0] === 0x1c && [0xb8, 0xbd].includes(p[1])) add("Zcash (transparent)", m[0], true);
    }
    // Bech32 / Bech32m segwit and Cosmos-style addresses
    const HRP = { bc: "Bitcoin (SegWit/Taproot)", tb: "Bitcoin testnet (SegWit)", ltc: "Litecoin (SegWit)", cosmos: "Cosmos (ATOM)", osmo: "Osmosis", bnb: "BNB Beacon Chain", terra: "Terra", addr: "Cardano (Shelley)", stake: "Cardano stake", zs: "Zcash (shielded Sapling)", inj: "Injective", sei: "Sei", celestia: "Celestia", juno: "Juno" };
    for (const m of text.matchAll(/\b(bc|tb|ltc|cosmos|osmo|bnb|terra|addr|stake|zs|inj|sei|celestia|juno)1[02-9ac-hj-np-z]{6,110}\b/gi))
        if (bech32Valid(m[0])) add(HRP[m[1].toLowerCase()], m[0], true);
    // Bitcoin Cash CashAddr (prefix optional)
    for (const m of text.matchAll(/\b(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}\b/g)) if (cashAddrValid(m[0])) add("Bitcoin Cash", m[0], true);
    // Ethereum and EVM chains (BSC, Polygon, Arbitrum …): 0x + 20 bytes
    for (const m of text.matchAll(/\b0x[0-9a-fA-F]{40}\b/g)) {
        const ok = eip55(m[0]);
        if (ok === false) continue; // mixed case with a wrong checksum: not an address
        add("Ethereum / EVM (ETH, BNB Smart Chain, Polygon …)", m[0], ok === true);
    }
    // Monero: 95 (standard/subaddress) or 106 (integrated) Base58 characters, prefix 4 or 8
    for (const m of text.matchAll(/\b[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?\b/g)) {
        const net = moneroCheck(m[0]);
        if (net === 18) add("Monero (XMR)", m[0], true); else if (net === 42) add("Monero (XMR) subaddress", m[0], true); else if (net === 19) add("Monero (XMR) integrated", m[0], true);
    }
    // Ripple: own Base58 alphabet, Base58Check
    for (const m of text.matchAll(/\br[1-9A-HJ-NP-Za-km-z]{24,34}\b/g)) { const p = b58check(m[0], XRP58); if (p && p.length === 21 && p[0] === 0) add("XRP (Ripple)", m[0], true); }
    // Stellar
    for (const m of text.matchAll(/\bG[A-Z2-7]{55}\b/g)) if (stellarValid(m[0])) add("Stellar (XLM)", m[0], true);
    // Tezos (Base58Check with 3-byte prefix)
    for (const m of text.matchAll(/\b(?:tz[123]|KT1)[1-9A-HJ-NP-Za-km-z]{33}\b/g)) { const p = b58check(m[0]); if (p && p.length === 23) add("Tezos (XTZ)", m[0], true); }
    // Polkadot / Kusama SS58 (checksum is BLAKE2b, not in Node: shape only, and only with context)
    if (/polkadot|\bdot\b|kusama|\bksm\b/i.test(text)) for (const m of text.matchAll(/\b[1C-HJ-NP-Za-km-z][1-9A-HJ-NP-Za-km-z]{46,47}\b/g)) { const b = b58decode(m[0]); if (b && b.length === 35) add("Polkadot / Kusama (SS58)", m[0], false); }
    // Solana: 32-byte Ed25519 key in Base58; only with context, the shape alone is too common
    if (/solana|\bsol\b|phantom|wallet/i.test(text)) for (const m of text.matchAll(/\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g)) { if (seen.has(m[0])) continue; const b = b58decode(m[0]); if (b && b.length === 32 && /\d/.test(m[0]) && /[a-z]/.test(m[0]) && /[A-Z]/.test(m[0])) add("Solana (SOL)", m[0], false); }
    // TON user-friendly address (36 bytes in Base64url, CRC16 at the end)
    for (const m of text.matchAll(/\b[EU]Q[A-Za-z0-9_-]{46}\b/g)) { const b = Buffer.from(m[0], "base64url"); if (b.length === 36 && crc16x(b.subarray(0, 34)) === b.readUInt16BE(34)) add("TON", m[0], true); }
    return out.slice(0, 50);
}

// ---------- hashes ----------
export function hashValues(text) {
    const out = [], seen = new Set();
    const L = { 32: "MD5 / NTLM", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512" };
    for (const m of text.matchAll(/(?<![0-9A-Za-z])(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128}|[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}|[0-9A-F]{128})(?![0-9A-Za-z])/g)) {
        const v = m[0];
        if (seen.has(v) || /^(.)\1+$/.test(v) || !/[a-fA-F]/.test(v) || !/\d/.test(v)) continue;
        seen.add(v); out.push({ type: L[v.length], value: v });
    }
    return out.slice(0, 50);
}

// ---------- host artefacts ----------
const PROCESSES = "cmd powershell pwsh rundll32 regsvr32 mshta wscript cscript certutil bitsadmin schtasks at wmic msiexec installutil regasm regsvcs msbuild cmstp forfiles mimikatz procdump psexec psexesvc lsass svchost explorer winlogon csrss services taskhost taskhostw conhost dllhost notepad calc vssadmin bcdedit wevtutil net net1 netsh nltest whoami ipconfig systeminfo tasklist taskkill reg sc ntdsutil esentutl mstsc wsl bash curl wget nc ncat python python3 perl java javaw cobaltstrike beacon chrome firefox msedge iexplore outlook winword excel powerpnt acrord32".split(" ");
const PROC_RE = new RegExp(`\\b(?:${PROCESSES.join("|")})\\.exe\\b`, "gi");
const FILE_EXT = "exe|dll|sys|scr|com|cpl|ocx|ps1|psm1|psd1|vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|lnk|jar|msi|msp|docm|dotm|xlsm|xlam|pptm|doc|docx|xls|xlsx|ppt|pptx|pdf|rtf|zip|rar|7z|gz|tar|iso|img|vhd|vhdx|txt|log|ini|cfg|conf|xml|json|csv|db|sqlite|dat|bin|tmp|py|pl|sh|elf|so|dylib|app|apk|dmg|pkg|deb|rpm|php|asp|aspx|jsp|html|htm|png|jpg|gif|key|pem|crt|pfx|kdbx|ost|pst|eml";
const FILE_RE = new RegExp(`(?<![\\w.-])[\\w$~-][\\w .$~-]{0,80}?\\.(?:${FILE_EXT})\\b`, "gi");

function windowsPaths(text) {
    const re = /(?:\b[A-Za-z]:\\|\\\\[\w.$-]+\\|%[A-Za-z_]+%\\|\$env:[A-Za-z_]+\\)(?:[^\\\/:*?"<>|\r\n\t%;]+\\)*[^\\\/:*?"<>|\r\n\t %;]*/g;
    return [...new Set((text.match(re) || []).map(p => p.replace(/[.,;)'"\]]+$/, "")).filter(p => p.length > 3))].slice(0, 50);
}
function registryPaths(text) {
    const re = /\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|Registry::HKEY_[A-Z_]+)(?::)?\\[^\s"'`;|<>]+/g;
    return [...new Set((text.match(re) || []).map(p => p.replace(/[.,)'"\]]+$/, "")))].slice(0, 50);
}
function userNames(text) {
    const out = new Set();
    const pats = [
        /\b[A-Za-z]:\\(?:Users|Documents and Settings)\\([^\\\/:*?"<>|\r\n\t ]+)/gi, // C:\Users\<name>
        /\/(?:home|Users)\/([a-z_][\w.-]{0,31})/g,                                    // /home/<name>
        /\bnet\s+user\s+(?:\/add\s+)?["']?([\w.$-]{2,32})/gi,                          // net user <name>
        /\b(?:useradd|adduser|usermod|userdel|New-LocalUser\s+(?:-Name\s+)?|-UserName\s+|-User\s+|--user(?:name)?[= ]|\/?\buser(?:name)?\s*[=:]\s*)["']?([\w.@$-]{2,32}(?:\\[\w.$-]{1,32})?)/gi,
        /(?<![:%$\w\\])([A-Z][A-Z0-9-]{1,14})\\([a-z][\w$-]{1,31})(?![\w.\\])/g,           // DOMAIN\user (not a path or file)
    ];
    for (const re of pats) for (const m of text.matchAll(re)) {
        const u = m[m.length - 1];
        if (m.length > 2 && m[1] && /^(TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|SYSTEMROOT|WINDIR|USERPROFILE|HOMEPATH|SYSTEM32|WINDOWS|SOFTWARE|SYSTEM|HKLM|HKCU|HKCR|HKU)$/i.test(m[1])) continue;
        if (!u || /^(public|default|all users|administrator\.?\w*|\*|%\w+%|\$env.*|add|delete)$/i.test(u) && !/administrator/i.test(u)) continue;
        out.add(m.length > 2 && m[1] && m[2] ? `${m[1]}\\${m[2]}` : u);
    }
    return [...out].filter(u => !/^(windows|system32|program|users)$/i.test(u)).slice(0, 50);
}

// ---------- people / places ----------
let COUNTRY_RE = null, COUNTRY_NAMES = null;
function countryNames(text) {
    if (!COUNTRY_RE) {
        const dn = new Intl.DisplayNames(["en"], { type: "region" });
        const names = new Set();
        for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
            const code = String.fromCharCode(a, b);
            let n; try { n = dn.of(code); } catch { continue; }
            if (n && n !== code && !/Unknown|Pseudo/i.test(n)) names.add(n.replace(/\s*\(.*\)$/, ""));
        }
        // common alternative forms
        ["USA", "United States of America", "UK", "Great Britain", "England", "Russian Federation", "Republic of Korea", "Iran (Islamic Republic of)", "DPRK", "Czech Republic", "Ivory Coast", "Burma", "Holland", "UAE"].forEach(n => names.add(n));
        COUNTRY_NAMES = [...names].filter(n => n.length >= 4 || /^(USA|UK|UAE)$/.test(n)).sort((x, y) => y.length - x.length);
        COUNTRY_RE = new RegExp(`\\b(?:${COUNTRY_NAMES.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b`, "g");
    }
    return [...new Set(text.match(COUNTRY_RE) || [])].slice(0, 50);
}
function phoneNumbers(text) {
    if (!phoneLib) return [];
    const out = [], seen = new Set();
    let found = [];
    try { found = phoneLib.findPhoneNumbersInText(text.slice(0, 200000), { defaultCountry: undefined, extended: false }); } catch { return []; }
    for (const f of found) {
        const n = f.number;
        if (!n.isValid() || seen.has(n.number)) continue;
        seen.add(n.number);
        const t = n.getType();
        const kind = t === "MOBILE" ? "Mobile" : t === "FIXED_LINE" ? "Landline" : t === "FIXED_LINE_OR_MOBILE" ? "Phone (landline or mobile)" : t === "TOLL_FREE" ? "Toll-free" : t === "VOIP" ? "VoIP" : "Phone";
        let country = n.country || "";
        try { if (country) country = new Intl.DisplayNames(["en"], { type: "region" }).of(country); } catch { /* keep code */ }
        out.push({ value: text.slice(f.startsAt, f.endsAt), number: n.number, kind, country });
    }
    return out.slice(0, 50);
}

// certificate, schema and OS-infrastructure hosts that appear in almost every signed binary or XML file
const BENIGN_HOSTS = /(^|\.)(schemas\.microsoft\.com|schemas\.openxmlformats\.org|w3\.org|xmlsoap\.org|purl\.org|digicert\.com|sectigo\.com|comodoca\.com|usertrust\.com|globalsign\.(com|net)|verisign\.com|symantec\.com|symcb\.com|symcd\.com|thawte\.com|entrust\.net|godaddy\.com|letsencrypt\.org|lencr\.org|identrust\.com|microsoft\.com\/pki|ocsp\.\w+\.\w+|crl\.\w+\.\w+|apple\.com\/appleca|adobe\.com\/xap|ns\.adobe\.com|openxmlformats\.org)$/i;
const benignUrl = u => { try { const h = new URL(u.replace(/^hxxp/i, "http")).hostname; return BENIGN_HOSTS.test(h); } catch { return false; } };

/**
 * All findings in a decoded output, each {category, type, value, level, note?}.
 * level: "high" (network indicators, wallets), "medium" (host artefacts, hashes, e-mail), "info".
 */
export function extractFindings(text) {
    const t = text.slice(0, 2_000_000);
    const io = extractIOCs(t);
    const F = [];
    const put = (category, type, value, level, note) => F.push({ category, type, value, level, ...(note ? { note } : {}) });
    [...new Set(io.urls.map(v => v.replace(/[.,;:!?'")\]}>]+$/, "")))].forEach(v => benignUrl(v) ? put("network", "URL", v, "info", "certificate / schema host") : put("network", "URL", v, "high"));
    io.ips.filter(v => !/^\d+\.\d+\.0\.0$/.test(v)).forEach(v => put("network", "IPv4 address", v, "high")); // "6.0.0.0" is a version number
    for (const m of new Set(t.match(/(?<![:\w])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![:\w])|(?<![:\w])(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5})?(?![:\w])/g) || [])) if (m.length > 6 && /[0-9a-f]/i.test(m) && m.split(":").filter(Boolean).length >= 3) put("network", "IPv6 address", m, "high");
    io.domains.forEach(v => BENIGN_HOSTS.test(v) ? put("network", "Domain", v, "info", "certificate / schema host") : put("network", "Domain", v, "high"));
    io.emails.forEach(v => put("network", "Email address", v, "medium"));
    cryptoAddresses(t).forEach(c => put("crypto", `${c.coin} address`, c.address, "high", c.checked ? "checksum verified" : "format match"));
    hashValues(t).forEach(h => put("hash", `${h.type} hash`, h.value, "medium"));
    registryPaths(t).forEach(v => put("host", "Registry path", v, "medium"));
    windowsPaths(t).forEach(v => put("host", "Windows path", v, "medium"));
    [...new Set(t.match(PROC_RE) || [])].slice(0, 50).forEach(v => put("host", "Process", v, "medium"));
    userNames(t).forEach(v => put("host", "User name", v, "medium"));
    const procs = new Set((t.match(PROC_RE) || []).map(x => x.toLowerCase()));
    [...new Set((t.match(FILE_RE) || []).map(x => x.trim()))].filter(f => !procs.has(f.toLowerCase()) && !io.domains.includes(f) && !/^\d+(\.\d+)+$/.test(f)).slice(0, 50).forEach(v => put("host", "File name", v, "info"));
    phoneNumbers(t).forEach(p => put("people", p.kind, p.value, "info", p.country ? `${p.country}, ${p.number}` : p.number));
    countryNames(t).forEach(v => put("people", "Country", v, "info"));
    for (const f of pluginFindings(t)) if (!F.some(x => x.value === f.value)) F.push(f);
    return F;
}

/** Short summary for alerts: {high, medium, info, byType:{type:count}} */
export function summarizeFindings(F) {
    const byType = {};
    for (const f of F) byType[f.type] = (byType[f.type] || 0) + 1;
    return { high: F.filter(f => f.level === "high").length, medium: F.filter(f => f.level === "medium").length, info: F.filter(f => f.level === "info").length, byType };
}
