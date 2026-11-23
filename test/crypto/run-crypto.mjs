/**
 * Ransomware & malware cryptography test.
 *
 * For every ransomware family MITRE ATT&CK lists under T1486 (families.json) and every
 * symmetric algorithm listed for it, real attacker command lines (Atomic Red Team) are
 * encrypted and AutoChef is tested in two situations:
 *
 *   KEY ABSENT  – what an encrypted victim file looks like: random key/nonce, nothing else.
 *                 Correct behaviour: NO fake "decoded" result, and the encrypted-data verdict.
 *   KEY PRESENT – the key/IV/nonce sit in the loader or config next to the ciphertext
 *                 (dropper scripts, leaked keys, config blobs). Correct behaviour: decrypted.
 *
 * Plus the documented config formats of REvil, Remcos, AsyncRAT/Quasar, DcRAT and the
 * Cobalt Strike PowerShell stager (sources in families.json). Config values are test values
 * (example.com, "TEST" ids), not real victim data.
 *
 * Encryption uses Node crypto and @noble/ciphers – independent of CyberChef – except RC6,
 * which neither provides; RC6 cases are encrypted with CyberChef's "RC6 Encrypt" (noted).
 *
 *   node test/crypto/run-crypto.mjs            (all cases)
 *   node test/crypto/run-crypto.mjs Conti      (one family)
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import { chacha20, chacha20orig, chacha8, xchacha20 } from "@noble/ciphers/chacha.js";
import { salsa20 } from "@noble/ciphers/salsa.js";
import { autoChef, runOps } from "../../src/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FAM = JSON.parse(fs.readFileSync(path.join(HERE, "families.json"), "utf8"));
const only = process.argv[2] || null;
let seed = 20261121;
const rng = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
const rnd = n => Buffer.from(Array.from({ length: n }, () => Math.floor(rng() * 256)));
const pick = a => a[Math.floor(rng() * a.length)];
const b64 = b => Buffer.from(b).toString("base64");
const hex = b => Buffer.from(b).toString("hex");

const commands = JSON.parse(fs.readFileSync(path.join(HERE, "..", "corpus", "art-commands.json"), "utf8"))
    .map(c => c.command.replace(/\r\n/g, "\n")).filter(c => c.length >= 60 && c.length <= 900 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(c));

function rc4(key, data) { // independent implementation for the test
    const S = [...Array(256).keys()]; let j = 0;
    for (let i = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 255; [S[i], S[j]] = [S[j], S[i]]; }
    const out = Buffer.alloc(data.length);
    for (let n = 0, i = 0, k = 0; n < data.length; n++) { i = (i + 1) & 255; k = (k + S[i]) & 255; [S[i], S[k]] = [S[k], S[i]]; out[n] = data[n] ^ S[(S[i] + S[k]) & 255]; }
    return out;
}
const aes = (bits, mode, key, iv, pt) => { const c = crypto.createCipheriv(`aes-${bits}-${mode}`, key, mode === "ecb" ? null : iv); return Buffer.concat([c.update(pt), c.final()]); };

// ---------- primitives (what MITRE's algorithm names map to) ----------
const PRIMS = {
    "AES-256-CBC": { key: 32, iv: 16, enc: (k, iv, p) => aes(256, "cbc", k, iv, p), api: "[Security.Cryptography.Aes]::Create() # CBC" },
    "AES-128-CBC": { key: 16, iv: 16, enc: (k, iv, p) => aes(128, "cbc", k, iv, p), api: "RijndaelManaged CBC" },
    "AES-256-CTR": { key: 32, iv: 16, enc: (k, iv, p) => aes(256, "ctr", k, iv, p), api: "AES-256-CTR" },
    "AES-256-ECB": { key: 32, iv: 0, enc: (k, iv, p) => aes(256, "ecb", k, null, p), api: "AES ECB" },
    "ChaCha20": { key: 32, iv: 12, enc: (k, n, p) => Buffer.from(chacha20(k, n, p)), api: "ChaCha20" },
    "ChaCha20-64bit-nonce": { key: 32, iv: 8, enc: (k, n, p) => Buffer.from(chacha20orig(k, n, p)), api: "ChaCha20 (original djb)" },
    "ChaCha8": { key: 32, iv: 12, enc: (k, n, p) => Buffer.from(chacha8(k, n, p)), api: "ChaCha8" },
    "Salsa20": { key: 32, iv: 8, enc: (k, n, p) => Buffer.from(salsa20(k, n, p)), api: "Salsa20" },
    "RC4": { key: 16, iv: 0, enc: (k, iv, p) => rc4(k, p), api: "RC4" },
    "RC6": { key: 16, iv: 16, cyberchefEncrypt: true, enc: async (k, iv, p) => Buffer.from(await runOps(new Uint8Array(p), [{ op: "RC6 Encrypt", args: [{ option: "Hex", string: hex(k) }, { option: "Hex", string: hex(iv) }, "CBC", "Raw", "Raw", "PKCS5", 32, 20] }])), api: "RC6" },
    "XChaCha20": { key: 32, iv: 24, unsupported: "CyberChef has no XChaCha20 operation", enc: (k, n, p) => Buffer.from(xchacha20(k, n, p)), api: "XChaCha20" },
};
const ASYMMETRIC = /RSA|ECDH|Curve25519|elliptic|NTRU/i;
const UNSUPPORTED = { Sosemanuk: "CyberChef has no Sosemanuk operation" };

function primitivesFor(alg) {
    const a = alg.toUpperCase();
    if (/^AES-128-CBC$/.test(a)) return ["AES-128-CBC"];
    if (/^AES-CBC$/.test(a)) return ["AES-256-CBC", "AES-128-CBC"];
    if (/^AES/.test(a)) return ["AES-256-CBC", "AES-256-CTR", "AES-256-ECB"];
    if (a === "CHACHA20" || a === "CHACHA") return ["ChaCha20", "ChaCha20-64bit-nonce"];
    if (a === "CHACHA8") return ["ChaCha8"];
    if (a === "SALSA20") return ["Salsa20"];
    if (a === "RC4") return ["RC4"];
    if (a === "RC6") return ["RC6"];
    if (a === "XCHACHA20") return ["XChaCha20"];
    return [];
}

// ---------- how key material appears in loaders ----------
const ENCODINGS = {
    hex: b => `"${hex(b)}"`,
    base64: b => `"${b64(b)}"`,
    bytes0x: b => `@(${[...b].map(x => "0x" + x.toString(16).padStart(2, "0")).join(",")})`,
    bytesDec: b => `[byte[]](${[...b].join(",")})`,
};
const TEMPLATES = {
    powershell: (api, k, iv, ct) => `# loader\n$key = ${k}\n${iv ? `$iv = ${iv}\n` : ""}$data = [Convert]::FromBase64String("${ct}")\n$c = New-Object ${api.replace(/[^\w.]/g, "")}Decryptor  # ${api} decrypt\n$out = $c.Decrypt($data, $key${iv ? ", $iv" : ""})\nIEX ([Text.Encoding]::UTF8.GetString($out))`,
    javascript: (api, k, iv, ct) => `// ${api} decrypt stage\nvar key = ${k.startsWith("@(") || k.startsWith("[byte") ? "[" + k.replace(/^@\(|^\[byte\[\]\]\(|\)$/g, "") + "]" : k};\n${iv ? `var iv = ${iv.startsWith("@(") || iv.startsWith("[byte") ? "[" + iv.replace(/^@\(|^\[byte\[\]\]\(|\)$/g, "") + "]" : iv};\n` : ""}var blob = atob("${ct}");\neval(decrypt(blob, key${iv ? ", iv" : ""}));`,
    python: (api, k, iv, ct) => `# ${api}\nkey = ${k.startsWith('"') ? "bytes.fromhex(" + k + ")" : k.replace(/^@\(|^\[byte\[\]\]\(/, "bytes([").replace(/\)$/, "])")}\n${iv ? `iv = ${iv.startsWith('"') ? "bytes.fromhex(" + iv + ")" : iv.replace(/^@\(|^\[byte\[\]\]\(/, "bytes([").replace(/\)$/, "])")}\n` : ""}blob = base64.b64decode("${ct}")\nexec(decrypt(key, ${iv ? "iv, " : ""}blob))`,
};

const cases = [];
const add = c => cases.push(c);

for (const fam of FAM.ransomware) {
    if (only && !fam.name.toLowerCase().includes(only.toLowerCase())) continue;
    const prims = [...new Set(fam.algorithms.flatMap(primitivesFor))];
    const notes = fam.algorithms.filter(a => ASYMMETRIC.test(a) || UNSUPPORTED[a]);
    // families listed only with asymmetric algorithms: their file data is still encrypted with some
    // per-file symmetric key; test the "key absent" verdict with AES-256-CBC and ChaCha20 data.
    const absentPrims = prims.length ? prims : ["AES-256-CBC", "ChaCha20"];
    for (const p of absentPrims) {
        for (let r = 0; r < (prims.length ? 4 : 6); r++) {
            add({ family: fam.name, source: fam.source, prim: p, scenario: "key-absent", note: notes.join(", "), make: async () => {
                const P = PRIMS[p];
                const plain = Buffer.from(pick(commands).repeat(3));
                const k = rnd(P.key), iv = rnd(P.iv || 16);
                const ct = await P.enc(k, iv, plain);
                // ransomware writes ciphertext (often with a footer holding the wrapped key); simulate the wrapped key as random bytes
                return { input: Buffer.concat([ct, rnd(r % 2 ? 256 : 0)]) };
            } });
        }
    }
    for (const p of prims) {
        const P = PRIMS[p];
        const variants = [];
        for (const tpl of Object.keys(TEMPLATES)) for (const encName of Object.keys(ENCODINGS)) variants.push({ tpl, encName, ivPlace: P.iv ? pick(["script", "prepended", "script"]) : "none" });
        for (const v of variants.slice(0, 12)) {
            add({ family: fam.name, source: fam.source, prim: p, scenario: "key-present", unsupported: P.unsupported, variant: `${v.tpl}/${v.encName}/iv-${v.ivPlace}`, make: async () => {
                const cmd = pick(commands);
                const k = rnd(P.key), iv = P.iv ? rnd(P.iv) : null;
                let ct = await P.enc(k, iv || Buffer.alloc(16), Buffer.from(cmd));
                if (v.ivPlace === "prepended") ct = Buffer.concat([iv, ct]);
                const text = TEMPLATES[v.tpl](P.api, ENCODINGS[v.encName](k), v.ivPlace === "script" ? ENCODINGS[v.encName](iv) : null, b64(ct));
                return { input: Buffer.from(text), needle: cmd.replace(/\s+/g, " ").trim().slice(0, 40) };
            } });
        }
    }
}

// ---------- documented malware config formats ----------
const crc32 = b => zlib.crc32 ? zlib.crc32(b) : 0;
if (!only || /revil|remcos|async|quasar|dcrat|cobalt/i.test(only)) {
    for (let i = 0; i < 20; i++) add({ family: "REvil / Sodinokibi (config)", source: FAM.configFormats[0].sources[0], prim: "RC4 (embedded key)", scenario: "key-present", variant: i % 2 ? "Base64 text" : "raw blob", make: async () => {
        const cfg = JSON.stringify({ pk: b64(rnd(32)), pid: "TEST-" + i, sub: String(1000 + i), dbg: false, et: 0, wipe: true, wht: { fld: ["windows", "program files"], fls: ["ntuser.dat"], ext: ["exe", "dll"] }, prc: ["sql", "outlook"], dmn: "example.com;example.org;example.net", net: false, nbody: b64(Buffer.from("TEST RANSOM NOTE PLACEHOLDER")), nname: "{EXT}-readme.txt", exp: false, img: b64(Buffer.from("TEST")) });
        const key = rnd(32), enc = rc4(key, Buffer.from(cfg));
        const len = Buffer.alloc(4); len.writeUInt32LE(enc.length);
        const crc = Buffer.alloc(4); crc.writeUInt32LE(crc32(enc) >>> 0);
        const blob = Buffer.concat([key, crc, len, enc]);
        return { input: i % 2 ? Buffer.from(b64(blob)) : blob, needle: '"dmn":"example.com;example.org' };
    } });
    for (let i = 0; i < 20; i++) add({ family: "Remcos (SETTINGS resource)", source: FAM.configFormats[1].sources[0], prim: "RC4 (embedded key)", scenario: "key-present", variant: i % 2 ? "Base64 text" : "raw blob", make: async () => {
        const D = "\x7c\x1f\x1e\x1e\x7c";
        const cfg = ["example.com:2404:1", "TEST-" + i, "1", "remcos.exe", "", "Remcos-TEST-MUTEX", "logs.dat", "Screenshots", "10"].join(D);
        const kl = 40 + Math.floor(rng() * 60), key = rnd(kl);
        const blob = Buffer.concat([Buffer.from([kl]), key, rc4(key, Buffer.from(cfg, "latin1"))]);
        return { input: i % 2 ? Buffer.from(b64(blob)) : blob, needle: "example.com:2404:1" };
    } });
    const ratCfg = (saltBuf, fam, srcIdx) => async i => {
        const master = b64(rnd(24)).replace(/[+/=]/g, "").slice(0, 32);
        const key = crypto.pbkdf2Sync(Buffer.from(master), saltBuf, 50000, 32, "sha1");
        const authKey = crypto.pbkdf2Sync(Buffer.from(master), saltBuf, 50000, 96, "sha1").subarray(32);
        const encField = v => { const iv = rnd(16); const ct = aes(256, "cbc", key, iv, Buffer.from(v)); const mac = crypto.createHmac("sha256", authKey).update(Buffer.concat([iv, ct])).digest(); return b64(Buffer.concat([mac, iv, ct])); };
        const text = `public static class Settings {\n  public static string Ports = "${encField("6606,7707,8808")}";\n  public static string Hosts = "${encField("test-c2.example.com")}";\n  public static string Version = "${encField("0.5.7B-TEST")}";\n  public static string Install = "${encField("false")}";\n  public static string MTX = "${encField("TEST_MUTEX_" + i)}";\n  public static string Key = "${b64(Buffer.from(master))}";\n}`;
        return { input: Buffer.from(text), needle: "test-c2.example.com" };
    };
    const asyncSalt = Buffer.from("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941", "hex");
    for (let i = 0; i < 20; i++) add({ family: "AsyncRAT / QuasarRAT (settings)", source: FAM.configFormats[2].sources[0], prim: "AES-256-CBC + PBKDF2", scenario: "key-present", variant: "settings class", make: () => ratCfg(asyncSalt)(i) });
    for (let i = 0; i < 20; i++) add({ family: "DcRAT (settings)", source: FAM.configFormats[3].sources[0], prim: "AES-256-CBC + PBKDF2", scenario: "key-present", variant: "settings class", make: () => ratCfg(Buffer.from("DcRatByqwqdanchun"))(i) });
    for (let i = 0; i < 20; i++) add({ family: "Cobalt Strike (PowerShell stager)", source: FAM.configFormats[4].sources[0], prim: "XOR 35", scenario: "key-present", variant: "stager", make: async () => {
        const sc = Buffer.concat([rnd(200), Buffer.from(`\x00User-Agent: Mozilla/5.0 (compatible; TEST ${i})\x00`), Buffer.from(`\x00198.51.100.${(i % 250) + 1}\x00`), rnd(100)]);
        const text = `Set-StrictMode -Version 2\n[Byte[]]$var_code = [System.Convert]::FromBase64String('${b64(Buffer.from(sc.map(x => x ^ 35)))}')\nfor ($x = 0; $x -lt $var_code.Count; $x++) { $var_code[$x] = $var_code[$x] -bxor 35 }`;
        return { input: Buffer.from(text), needle: `198.51.100.${(i % 250) + 1}` };
    } });
}

// ---------- run ----------
const t0 = Date.now();
const stats = {};
const failures = [];
let n = 0;
for (const c of cases) {
    const { input, needle } = await c.make();
    const res = await autoChef(new Uint8Array(input), { timeBudgetMs: 8000, maxResults: 5 });
    const outs = res.results.map(r => (r.output.base64 ? Buffer.from(r.output.base64, "base64").toString("latin1") : (r.output.preview || "")).replace(/\s+/g, " "));
    let ok1, ok5;
    if (c.scenario === "key-absent") {
        // correct = no medium/high-confidence "decoded" claim AND the encrypted verdict
        const falseClaim = res.results.some(r => r.confidence !== "low");
        ok1 = ok5 = !falseClaim && !!res.assessment;
    } else {
        ok1 = !!outs[0] && outs[0].includes(needle);
        ok5 = outs.some(o => o.includes(needle));
    }
    const key = `${c.family}|${c.prim}|${c.scenario}`;
    const s = stats[key] ||= { family: c.family, source: c.source, prim: c.prim, scenario: c.scenario, unsupported: c.unsupported || null, note: c.note || "", n: 0, top1: 0, top5: 0 };
    s.n++; s.top1 += ok1; s.top5 += ok5;
    if (!ok5) failures.push({ family: c.family, prim: c.prim, scenario: c.scenario, variant: c.variant, got: res.results[0]?.recipe.map(o => o.op).join(" > ") || null, assessment: !!res.assessment });
    if (++n % 50 === 0) console.log(`${n}/${cases.length}  (${Math.round((Date.now() - t0) / 1000)} s)`);
}

const rows = Object.values(stats);
const tot = sc => rows.filter(r => r.scenario === sc && !r.unsupported).reduce((a, r) => ({ n: a.n + r.n, t1: a.t1 + r.top1, t5: a.t5 + r.top5 }), { n: 0, t1: 0, t5: 0 });
console.log("\nfamily | primitive | scenario | top-1 | top-5");
for (const r of rows) console.log(`${r.family} | ${r.prim} | ${r.scenario}${r.unsupported ? " (unsupported: " + r.unsupported + ")" : ""} | ${r.top1}/${r.n} | ${r.top5}/${r.n}`);
const kp = tot("key-present"), ka = tot("key-absent");
const famCount = new Set(rows.map(r => r.family)).size;
console.log(`\nCases: ${cases.length} across ${famCount} families/formats, ${Math.round((Date.now() - t0) / 1000)} s`);
console.log(`KEY PRESENT (supported ciphers): decrypted as #1 ${kp.t1}/${kp.n} (${(100 * kp.t1 / kp.n).toFixed(1)}%), in top 5 ${kp.t5}/${kp.n} (${(100 * kp.t5 / kp.n).toFixed(1)}%)`);
console.log(`KEY ABSENT: correctly reported as encrypted with no false decode ${ka.t1}/${ka.n} (${(100 * ka.t1 / ka.n).toFixed(1)}%)`);
const uns = rows.filter(r => r.unsupported);
if (uns.length) console.log(`Unsupported by CyberChef (expected to fail): ${uns.map(r => `${r.family} ${r.prim} ${r.top5}/${r.n}`).join("; ")}`);
fs.writeFileSync(path.join(HERE, "crypto-report.json"), JSON.stringify({ cases: cases.length, families: famCount, keyPresent: kp, keyAbsent: ka, rows, failures }, null, 1));
process.exit(0);
