/**
 * Obfuscation chains used to build the 1000+ case test corpus.
 * Each chain reproduces a technique seen in real malware / public tooling; the
 * reference column says where it comes from. Encoding is done with Node's own
 * libraries only (never CyberChef), so the test can't simply agree with itself.
 */
import zlib from "node:zlib";
import crypto from "node:crypto";

const b64 = b => Buffer.from(b).toString("base64");
const hex = b => Buffer.from(b).toString("hex");
const u16 = s => Buffer.from(s, "utf16le");
const rev = s => [...s].reverse().join("");
const rot = (s, k) => s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - o + k) % 26 + o); });
const xor = (b, key) => Buffer.from(Buffer.from(b).map((x, i) => x ^ key[i % key.length]));
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32(buf) {
    let bits = "", out = "";
    for (const b of Buffer.from(buf)) bits += b.toString(2).padStart(8, "0");
    for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
    while (out.length % 8) out += "=";
    return out;
}
function rc4(key, data) {
    const S = [...Array(256).keys()];
    for (let i = 0, j = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 255; [S[i], S[j]] = [S[j], S[i]]; }
    const out = Buffer.alloc(data.length);
    for (let n = 0, i = 0, j = 0; n < data.length; n++) { i = (i + 1) & 255; j = (j + S[i]) & 255; [S[i], S[j]] = [S[j], S[i]]; out[n] = data[n] ^ S[(S[i] + S[j]) & 255]; }
    return out;
}
const chunk = (s, n) => s.match(new RegExp(`.{1,${n}}`, "g")) || [];

/** rng: () => [0,1) ; each chain returns the obfuscated text (or Buffer for binary) */
export const CHAINS = [
    { id: "b64", ref: "Plain Base64 (ubiquitous)", make: c => b64(c) },
    { id: "ps-enc", ref: "PowerShell -EncodedCommand (UTF-16LE Base64)", make: c => `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand ${b64(u16(c))}` },
    { id: "ps-gzip", ref: "PowerShell GzipStream loader (Cobalt Strike / Empire style)", make: c => `$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("${b64(zlib.gzipSync(c))}"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()` },
    { id: "ps-deflate", ref: "Invoke-Obfuscation compression launcher (DeflateStream)", make: c => `.((gv '*mdr*').NaMe[3,11,2]-JoiN'')(NEw-OBjeCt IO.StrEAmREADer((NEw-OBjeCt IO.CompRESSiON.DeFLateSTrEAm([IO.MemORyStREAm][CoNVErt]::FROmbase64sTRing('${b64(zlib.deflateRawSync(c))}'),[SysTEM.Io.ComPReSsIOn.CoMPresSiONmODE]::DEcOmprEss)),[TExT.EncoDinG]::AsCIi)).rEADtOEnd()` },
    { id: "hex", ref: "Hex string payload", make: c => hex(c) },
    { id: "ps-char", ref: "PowerShell [char] code concatenation", make: c => `IEX (${[...c].map(ch => `[char]${ch.charCodeAt(0)}`).join("+")})` },
    { id: "ps-join", ref: "PowerShell byte array join (-join [char[]])", make: c => `iex(-join [char[]](${[...Buffer.from(c)].join(",")}))` },
    { id: "rev-b64", ref: "Reversed Base64 (e.g. AgentTesla/AsyncRAT loaders)", make: c => rev(b64(c)) },
    { id: "url", ref: "Full URL (percent) encoding", make: c => [...Buffer.from(c)].map(b => "%" + b.toString(16).padStart(2, "0")).join("") },
    { id: "b64-xor-hint", ref: "Base64 + single-byte XOR with -bxor key in the loader", make: (c, r) => { const k = 1 + Math.floor(r() * 254); return `$b=[Convert]::FromBase64String('${b64(xor(c, [k]))}');$d=foreach($x in $b){$x -bxor ${k}};iex([Text.Encoding]::ASCII.GetString($d))`; } },
    { id: "b64-xor", ref: "Base64 of single-byte XOR (key not in sample)", make: (c, r) => b64(xor(c, [1 + Math.floor(r() * 254)])) },
    { id: "rot13", ref: "ROT13", make: c => rot(c, 13) },
    { id: "base32", ref: "Base32", make: c => base32(c) },
    { id: "b64-gzip-u16", ref: "Base64(Gzip(UTF-16LE)) three layers", make: c => b64(zlib.gzipSync(u16(c))) },
    { id: "js-fromcharcode", ref: "JavaScript String.fromCharCode() loader", make: c => `eval(String.fromCharCode(${[...Buffer.from(c)].join(",")}));` },
    { id: "js-unicode", ref: "JavaScript \\u escapes", make: c => `var s="${[...c].map(ch => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0")).join("")}";eval(s);` },
    { id: "js-hex-esc", ref: "JavaScript \\x escapes", make: c => `var _0x1a2b="${[...Buffer.from(c)].map(b => "\\x" + b.toString(16).padStart(2, "0")).join("")}";eval(_0x1a2b);` },
    { id: "vba-chr", ref: "VBA Chr() concatenation (maldocs)", make: c => `Sub AutoOpen()\r\nDim s As String\r\ns = ${[...c].map(ch => `Chr(${ch.charCodeAt(0)})`).join(" & ")}\r\nCreateObject("WScript.Shell").Run s, 0\r\nEnd Sub` },
    { id: "b64-junk", ref: "Base64 with a junk token substituted for 'A' (seen in JS droppers)", make: c => b64(Buffer.concat([Buffer.alloc(3), Buffer.from(c)])).split("A").join("@<!") },
    { id: "multi-b64", ref: "Script with several Base64 strings", make: c => { const half = Math.ceil(c.length / 2); return `$a = "${b64(c.slice(0, half))}"\n$b = "${b64(c.slice(half))}"\n$c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a)) + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b))\nIEX $c`; }, needlePart: true },
    { id: "ps-aes", ref: "PowerShell AES-CBC loader with key/IV in the script", make: (c, r, rnd) => {
        const key = rnd(32), iv = rnd(16);
        const ci = crypto.createCipheriv("aes-256-cbc", key, iv);
        const enc = Buffer.concat([ci.update(c), ci.final()]);
        return `$k=[Convert]::FromBase64String("${b64(key)}")\n$i=[Convert]::FromBase64String("${b64(iv)}")\n$a=[Security.Cryptography.Aes]::Create();$a.Key=$k;$a.IV=$i\n$d=$a.CreateDecryptor().TransformFinalBlock([Convert]::FromBase64String("${b64(enc)}"),0,${enc.length})\niex([Text.Encoding]::UTF8.GetString($d))`;
    } },
    { id: "js-rc4", ref: "JavaScript RC4 decryptor with key string", make: (c, r) => {
        const key = Buffer.from(["update", "k3y", "s3cr3tK", "Xq9z", "loader", "p4ss"][Math.floor(r() * 6)] + Math.floor(r() * 1000));
        return `function rc4(key, str) { /* standard RC4 */ }\nvar k = "${key.toString()}";\nvar data = atob("${b64(rc4(key, Buffer.from(c)))}");\neval(rc4(k, data));`;
    } },
    { id: "rolling-xor-hex", ref: "Rolling XOR (key increments every byte), hex encoded", make: (c, r) => { const k = Math.floor(r() * 256); return hex(Buffer.from(Buffer.from(c).map((x, i) => x ^ ((k + i) & 255)))); } },
    { id: "multi-xor-b64", ref: "Multi-byte XOR key, Base64 (key visible in script)", make: (c, r) => { const key = ["infected", "Sup3rK3y", "x0r!", "AbCd1234"][Math.floor(r() * 4)]; return `key = "${key}"\nblob = "${b64(xor(c, Buffer.from(key)))}"\nexec(xor(b64decode(blob), key))`; } },
    { id: "split-concat", ref: "Base64 split into concatenated string fragments", make: c => `$p = ${chunk(b64(u16(c)), 20).map(x => `'${x}'`).join("+")};powershell -enc $p` },
    { id: "b64-b64", ref: "Double Base64", make: c => b64(b64(c)) },
    { id: "hex-b64-rev", ref: "Hex → reversed → Base64 (layered, like VBS droppers)", make: c => b64(rev(hex(c))) },
    { id: "cmd-caret", ref: "cmd.exe caret obfuscation (DOSfuscation)", make: (c, r) => `cmd /c "${c.replace(/[a-z]/gi, ch => r() < 0.5 ? "^" + ch : ch)}"` },
    { id: "html-entity", ref: "HTML numeric entities", make: c => [...c].map(ch => `&#${ch.charCodeAt(0)};`).join("") },
    { id: "zlib-b64", ref: "Zlib + Base64 (PHP gzcompress style)", make: c => `<?php eval(gzuncompress(base64_decode('${b64(zlib.deflateSync(c))}'))); ?>` },
];
