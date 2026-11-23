/**
 * Static analysis of Windows executables (PE32 / PE32+): headers, sections with entropy, imports
 * (with imphash), exports, resources, .NET, PDB path, signature and overlay. Nothing is executed.
 * Layout per Microsoft's "PE Format" documentation.
 */
import crypto from "node:crypto";

const MACHINES = { 0x14c: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x1c0: "ARM", 0xaa64: "ARM64", 0x1c4: "ARMv7 Thumb-2", 0x200: "IA-64" };
const SUBSYS = { 1: "Native", 2: "Windows GUI", 3: "Windows console", 9: "Windows CE GUI", 10: "EFI application", 14: "Xbox" };
const RES_TYPES = { 1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST" };
// imports that matter when triaging malware (injection, download, persistence, crypto, anti-analysis)
const NOTABLE = /^(VirtualAlloc(Ex)?|VirtualProtect(Ex)?|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread(Ex)?|NtCreateThreadEx|QueueUserAPC|SetThreadContext|ResumeThread|NtUnmapViewOfSection|ZwUnmapViewOfSection|LoadLibrary[AW]?|GetProcAddress|URLDownloadToFile[AW]?|InternetOpen(Url)?[AW]?|InternetReadFile|HttpSendRequest[AW]?|WinHttpOpen|WinHttpSendRequest|WSAStartup|connect|ShellExecute(Ex)?[AW]?|WinExec|CreateProcess[AW]?|RegSetValue(Ex)?[AW]?|RegCreateKey(Ex)?[AW]?|CryptEncrypt|CryptDecrypt|CryptAcquireContext[AW]?|BCryptEncrypt|BCryptDecrypt|IsDebuggerPresent|CheckRemoteDebuggerPresent|SetWindowsHookEx[AW]?|GetAsyncKeyState|OpenProcess|AdjustTokenPrivileges|CreateService[AW]?|StartService[AW]?|DeleteShadowCopies|MiniDumpWriteDump)$/;

const entropyOf = b => { if (!b.length) return 0; const f = new Array(256).fill(0); for (const x of b) f[x]++; let e = 0; for (const c of f) if (c) { const p = c / b.length; e -= p * Math.log2(p); } return +e.toFixed(2); };

export function isPE(b) {
    if (b.length < 64 || b[0] !== 0x4d || b[1] !== 0x5a) return false;
    const off = Buffer.from(b).readUInt32LE(0x3c);
    return off > 0 && off + 4 < b.length && b[off] === 0x50 && b[off + 1] === 0x45 && b[off + 2] === 0 && b[off + 3] === 0;
}

export function analyzePE(input) {
    const b = Buffer.from(input);
    if (!isPE(b)) return null;
    const pe = b.readUInt32LE(0x3c), coff = pe + 4;
    const machine = b.readUInt16LE(coff), nSec = b.readUInt16LE(coff + 2), ts = b.readUInt32LE(coff + 4), optSize = b.readUInt16LE(coff + 16), chars = b.readUInt16LE(coff + 18);
    const opt = coff + 20, magic = b.readUInt16LE(opt), is64 = magic === 0x20b;
    const entry = b.readUInt32LE(opt + 16);
    const imageBase = is64 ? b.readBigUInt64LE(opt + 24) : BigInt(b.readUInt32LE(opt + 28));
    const subsystem = b.readUInt16LE(opt + 68), dllChars = b.readUInt16LE(opt + 70);
    const ddOff = opt + (is64 ? 112 : 96), nDD = Math.min(16, b.readUInt32LE(opt + (is64 ? 108 : 92)));
    const dd = i => i < nDD ? { rva: b.readUInt32LE(ddOff + i * 8), size: b.readUInt32LE(ddOff + i * 8 + 4) } : { rva: 0, size: 0 };
    const secOff = opt + optSize;
    const sections = [];
    for (let i = 0; i < nSec && secOff + i * 40 + 40 <= b.length; i++) {
        const o = secOff + i * 40;
        const s = { name: b.subarray(o, o + 8).toString("latin1").replace(/\0.*$/, ""), vsize: b.readUInt32LE(o + 8), va: b.readUInt32LE(o + 12), rawSize: b.readUInt32LE(o + 16), rawPtr: b.readUInt32LE(o + 20), chars: b.readUInt32LE(o + 36) };
        s.entropy = entropyOf(b.subarray(s.rawPtr, Math.min(b.length, s.rawPtr + s.rawSize)));
        s.flags = [(s.chars & 0x20000000) && "exec", (s.chars & 0x40000000) && "read", (s.chars & 0x80000000) && "write"].filter(Boolean).join(",");
        sections.push(s);
    }
    const off = rva => { for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return rva - s.va + s.rawPtr; return rva < b.length ? rva : -1; };
    const cstr = (o, max = 512) => { if (o < 0 || o >= b.length) return ""; let e = o; while (e < b.length && e - o < max && b[e]) e++; return b.subarray(o, e).toString("latin1"); };

    // imports
    const imports = [];
    const imp = dd(1);
    if (imp.rva) {
        for (let d = off(imp.rva), n = 0; d >= 0 && d + 20 <= b.length && n < 512; d += 20, n++) {
            const oft = b.readUInt32LE(d), nameRva = b.readUInt32LE(d + 12), ft = b.readUInt32LE(d + 16);
            if (!oft && !nameRva && !ft) break;
            const dll = cstr(off(nameRva));
            const funcs = [];
            for (let t = off(oft || ft), k = 0; t >= 0 && k < 4096; t += is64 ? 8 : 4, k++) {
                if (t + (is64 ? 8 : 4) > b.length) break;
                const v = is64 ? b.readBigUInt64LE(t) : BigInt(b.readUInt32LE(t));
                if (!v) break;
                const ordinal = is64 ? (v >> 63n) & 1n : (v >> 31n) & 1n;
                if (ordinal) funcs.push({ ordinal: Number(v & 0xffffn) });
                else funcs.push({ name: cstr(off(Number(v & 0x7fffffffn)) + 2) });
            }
            imports.push({ dll, funcs });
        }
    }
    // imphash (pefile convention; ordinals written as "ord<N>")
    const parts = [];
    for (const i of imports) {
        const lib = i.dll.toLowerCase().replace(/\.(dll|ocx|sys)$/, "");
        for (const f of i.funcs) parts.push(`${lib}.${f.name ? f.name.toLowerCase() : "ord" + f.ordinal}`);
    }
    const imphash = parts.length ? crypto.createHash("md5").update(parts.join(",")).digest("hex") : null;

    // exports
    const exports = [];
    let dllName = null;
    const ex = dd(0);
    if (ex.rva && off(ex.rva) >= 0) {
        const e = off(ex.rva);
        dllName = cstr(off(b.readUInt32LE(e + 12)));
        const nNames = b.readUInt32LE(e + 24), namesRva = b.readUInt32LE(e + 32);
        for (let i = 0; i < Math.min(nNames, 2000); i++) { const p = off(namesRva) + i * 4; if (p < 0 || p + 4 > b.length) break; exports.push(cstr(off(b.readUInt32LE(p)))); }
    }
    // resources: type -> count
    const resources = {};
    const rs = dd(2);
    if (rs.rva && off(rs.rva) >= 0) {
        const base = off(rs.rva);
        const nEntries = o => b.readUInt16LE(o + 12) + b.readUInt16LE(o + 14);
        const countLeaves = (o, depth) => { if (depth > 3 || o + 16 > b.length) return 0; let n = 0; for (let i = 0; i < nEntries(o) && i < 512; i++) { const e = o + 16 + i * 8; if (e + 8 > b.length) break; const v = b.readUInt32LE(e + 4); n += v & 0x80000000 ? countLeaves(base + (v & 0x7fffffff), depth + 1) : 1; } return n; };
        for (let i = 0; i < nEntries(base) && i < 64; i++) {
            const e = base + 16 + i * 8; if (e + 8 > b.length) break;
            const id = b.readUInt32LE(e), v = b.readUInt32LE(e + 4);
            let name = RES_TYPES[id] || `#${id}`;
            if (id & 0x80000000) { const so = base + (id & 0x7fffffff); name = b.subarray(so + 2, so + 2 + b.readUInt16LE(so) * 2).toString("utf16le"); }
            resources[name] = v & 0x80000000 ? countLeaves(base + (v & 0x7fffffff), 1) : 1;
        }
    }
    // PDB path (CodeView RSDS in the debug directory)
    let pdb = null;
    const dbg = dd(6);
    if (dbg.rva && off(dbg.rva) >= 0) for (let d = off(dbg.rva), k = 0; k < dbg.size / 28 && k < 16; d += 28, k++) {
        if (d + 28 > b.length) break;
        if (b.readUInt32LE(d + 12) === 2) { const p = b.readUInt32LE(d + 24); if (p + 24 < b.length && b.subarray(p, p + 4).toString("latin1") === "RSDS") pdb = cstr(p + 24, 260); }
    }
    const sec = dd(4);
    const lastRaw = Math.max(0, ...sections.map(s => s.rawPtr + s.rawSize));
    const overlay = Math.max(0, (sec.rva && sec.rva >= lastRaw ? sec.rva : b.length) - lastRaw);
    const notable = [...new Set(imports.flatMap(i => i.funcs.map(f => f.name).filter(n => n && NOTABLE.test(n))))];
    const warnings = [];
    if (sections.some(s => s.entropy > 7.2 && s.name !== ".rsrc")) warnings.push("high-entropy code/data section (packed or encrypted)");
    if (sections.some(s => s.flags.includes("exec") && s.flags.includes("write"))) warnings.push("section that is both writable and executable");
    if (imports.length && imports.reduce((a, i) => a + i.funcs.length, 0) < 10) warnings.push("very few imports (often a packer stub)");
    if (entry && !sections.some(s => entry >= s.va && entry < s.va + Math.max(s.vsize, s.rawSize))) warnings.push("entry point outside every section");
    if (ts > Date.now() / 1000 + 86400) warnings.push("compile time in the future (forged timestamp)");
    return {
        format: is64 ? "PE32+" : "PE32", machine: MACHINES[machine] || `0x${machine.toString(16)}`, type: chars & 0x2000 ? "DLL" : "EXE",
        dotnet: !!dd(14).rva, subsystem: SUBSYS[subsystem] || subsystem, compiled: new Date(ts * 1000).toISOString(), timestamp: ts,
        entryPoint: "0x" + entry.toString(16), imageBase: "0x" + imageBase.toString(16),
        aslr: !!(dllChars & 0x40), dep: !!(dllChars & 0x100), signed: !!sec.rva, overlay, pdb, dllName,
        sections: sections.map(({ chars, ...s }) => s), imports: imports.map(i => ({ dll: i.dll, count: i.funcs.length, functions: i.funcs.slice(0, 300).map(f => f.name || `#${f.ordinal}`) })),
        imphash, exports: exports.slice(0, 300), resources, notableImports: notable, warnings,
        sha256: crypto.createHash("sha256").update(b).digest("hex"),
    };
}
