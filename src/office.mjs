/**
 * Office document macro extraction (static: nothing is executed).
 *
 *  - OLE2 / Compound File Binary (.doc, .xls, .ppt, vbaProject.bin)  [MS-CFB]
 *  - VBA project: "dir" stream records and module source             [MS-OVBA 2.3.4.2]
 *  - MS-OVBA run-length compression                                   [MS-OVBA 2.4.1]
 *  - Office Open XML (.docm, .xlsm, .pptm, .docx …): vbaProject.bin inside the zip
 *
 * CyberChef has no operation for this, so it is a pre-processing step: AutoChef shows the extracted
 * macro source and then searches for a CyberChef recipe on that text.
 */
import { ZipReader, Uint8ArrayReader, Uint8ArrayWriter } from "@zip.js/zip.js";

const OLE_MAGIC = "d0cf11e0a1b11ae1";
export const isOle = b => b.length > 512 && Buffer.from(b.subarray(0, 8)).toString("hex") === OLE_MAGIC;
export const isZip = b => b.length > 30 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4;

/** Parse a compound file. Returns {streams: Map(path -> Buffer)} */
export function parseOle(input) {
    const b = Buffer.from(input);
    const secSize = 1 << b.readUInt16LE(0x1e), miniSize = 1 << b.readUInt16LE(0x20);
    const nFat = b.readUInt32LE(0x2c), dirStart = b.readUInt32LE(0x30), miniCutoff = b.readUInt32LE(0x38);
    const miniFatStart = b.readUInt32LE(0x3c), difatStart = b.readUInt32LE(0x44), nDifat = b.readUInt32LE(0x48);
    if (secSize !== 512 && secSize !== 4096) throw new Error("not a compound file (sector size)");
    const sector = n => b.subarray(512 + n * secSize, 512 + (n + 1) * secSize);
    const ENDS = 0xfffffffe;
    // FAT sector list from the header DIFAT (109 entries) and the DIFAT chain
    const fatSecs = [];
    for (let i = 0; i < 109 && fatSecs.length < nFat; i++) { const s = b.readUInt32LE(0x4c + i * 4); if (s < 0xfffffffa) fatSecs.push(s); }
    for (let d = difatStart, k = 0; d < 0xfffffffa && k < nDifat && fatSecs.length < nFat; k++) {
        const s = sector(d);
        for (let i = 0; i < secSize / 4 - 1 && fatSecs.length < nFat; i++) { const v = s.readUInt32LE(i * 4); if (v < 0xfffffffa) fatSecs.push(v); }
        d = s.readUInt32LE(secSize - 4);
    }
    const fat = [];
    for (const fs of fatSecs) { const s = sector(fs); for (let i = 0; i < secSize; i += 4) fat.push(s.readUInt32LE(i)); }
    const chain = (start, max = 1e6) => {
        const out = [];
        for (let s = start, n = 0; s < 0xfffffffa && n < max && s < fat.length; n++) { out.push(s); s = fat[s]; }
        return out;
    };
    const readChain = start => Buffer.concat(chain(start).map(sector));
    // directory
    const dir = readChain(dirStart);
    const entries = [];
    for (let o = 0; o + 128 <= dir.length; o += 128) {
        const nameLen = dir.readUInt16LE(o + 0x40);
        const type = dir[o + 0x42];
        if (!type) { entries.push(null); continue; }
        entries.push({
            name: dir.subarray(o, o + Math.max(0, nameLen - 2)).toString("utf16le"), type,
            left: dir.readUInt32LE(o + 0x44), right: dir.readUInt32LE(o + 0x48), child: dir.readUInt32LE(o + 0x4c),
            start: dir.readUInt32LE(o + 0x74), size: dir.readUInt32LE(o + 0x78),
        });
    }
    const root = entries[0];
    if (!root || root.type !== 5) throw new Error("no root entry");
    const miniStream = readChain(root.start);
    const miniFat = [];
    for (const s of chain(miniFatStart)) { const sec = sector(s); for (let i = 0; i < secSize; i += 4) miniFat.push(sec.readUInt32LE(i)); }
    const readMini = (start, size) => {
        const parts = [];
        for (let s = start, n = 0; s < 0xfffffffa && n < 1e6 && s < miniFat.length; n++) { parts.push(miniStream.subarray(s * miniSize, (s + 1) * miniSize)); s = miniFat[s]; }
        return Buffer.concat(parts).subarray(0, size);
    };
    const streams = new Map();
    const seen = new Set();
    const walk = (idx, prefix) => {
        if (idx >= entries.length || idx === 0xffffffff || seen.has(idx)) return;
        seen.add(idx);
        const e = entries[idx];
        if (!e) return;
        walk(e.left, prefix); walk(e.right, prefix);
        const p = prefix ? `${prefix}/${e.name}` : e.name;
        if (e.type === 2) streams.set(p, e.size < miniCutoff ? readMini(e.start, e.size) : readChain(e.start).subarray(0, e.size));
        if (e.type === 1) walk(e.child, p);
    };
    walk(root.child, "");
    return { streams };
}

/** MS-OVBA 2.4.1 decompression */
export function ovbaDecompress(c) {
    if (!c.length || c[0] !== 1) throw new Error("bad compressed container signature");
    const out = [];
    let p = 1;
    while (p + 2 <= c.length) {
        const hdr = c.readUInt16LE(p);
        const size = (hdr & 0x0fff) + 3, compressed = hdr >> 15;
        const end = Math.min(p + size, c.length);
        p += 2;
        const start = out.length;
        if (!compressed) { for (let i = 0; i < 4096 && p < end; i++) out.push(c[p++]); continue; }
        while (p < end) {
            const flags = c[p++];
            for (let bit = 0; bit < 8 && p < end; bit++) {
                if (!((flags >> bit) & 1)) { out.push(c[p++]); continue; }
                if (p + 2 > end) { p = end; break; }
                const tok = c.readUInt16LE(p); p += 2;
                const dpos = out.length - start;
                let bc = 4; while ((1 << bc) < dpos) bc++;
                bc = Math.max(bc, 4);
                const lenMask = 0xffff >> bc;
                const off = (tok >> (16 - bc)) + 1, len = (tok & lenMask) + 3;
                for (let i = 0; i < len; i++) out.push(out[out.length - off]);
            }
        }
    }
    return Buffer.from(out);
}

/** Modules {name, stream, code} from the VBA project streams found in a compound file */
export function vbaModules(streams) {
    const out = [];
    const dirPaths = [...streams.keys()].filter(k => /(^|\/)VBA\/dir$/i.test(k));
    for (const dp of dirPaths) {
        const base = dp.slice(0, -3);
        let d;
        try { d = ovbaDecompress(streams.get(dp)); } catch { continue; }
        let codepage = 1252, cur = null;
        const mods = [];
        for (let o = 0; o + 6 <= d.length;) {
            const id = d.readUInt16LE(o);
            let size = d.readUInt32LE(o + 2);
            if (id === 0x0009) size = 6; // PROJECTVERSION: size field is "reserved", data is 6 bytes
            const data = d.subarray(o + 6, o + 6 + size);
            o += 6 + size;
            if (id === 0x0003 && data.length >= 2) codepage = data.readUInt16LE(0);
            else if (id === 0x0019) { cur = { name: data.toString("latin1"), stream: null, offset: 0 }; mods.push(cur); }
            else if (id === 0x001a && cur) cur.stream = data.toString("latin1");
            else if (id === 0x0031 && cur && data.length >= 4) cur.offset = data.readUInt32LE(0);
            else if (id === 0x0010) break; // end of PROJECTMODULES
        }
        for (const m of mods) {
            const sp = base + (m.stream || m.name);
            const key = [...streams.keys()].find(k => k.toLowerCase() === sp.toLowerCase());
            if (!key) continue;
            try {
                const code = ovbaDecompress(streams.get(key).subarray(m.offset));
                out.push({ name: m.name, stream: key, codepage, code: decodeCp(code, codepage) });
            } catch { /* damaged module: skip */ }
        }
    }
    return out;
}
function decodeCp(buf, cp) {
    const map = { 1252: "windows-1252", 1251: "windows-1251", 1250: "windows-1250", 932: "shift_jis", 936: "gbk", 949: "euc-kr", 950: "big5", 65001: "utf-8" };
    try { return new TextDecoder(map[cp] || "windows-1252").decode(buf); } catch { return buf.toString("latin1"); }
}

/** Long printable runs (ASCII and UTF-16LE) – where Emotet-style documents hide their payload */
function longStrings(b, min = 60) {
    const out = [];
    const ascii = b.toString("latin1").match(new RegExp(`[\\x20-\\x7e\\t]{${min},}`, "g")) || [];
    out.push(...ascii);
    for (const off of [0, 1]) {
        const u = b.subarray(off, b.length - ((b.length - off) % 2)).toString("utf16le");
        out.push(...(u.match(new RegExp(`[\\x20-\\x7e\\t]{${min},}`, "g")) || []));
    }
    return [...new Set(out)].filter(x => !/^(.)\1+$/.test(x)).slice(0, 50);
}

/**
 * Extract macros from an Office file. Returns null when the input is not Office, otherwise
 * {container, modules:[{name, code}], streams:[names], text} – text is all module source joined.
 */
export async function extractOffice(bytes) {
    const b = Buffer.from(bytes);
    let container = null, modules = [], streams = [], embedded = [];
    if (isOle(b)) {
        container = "OLE2 compound file (.doc/.xls/.ppt)";
        const ole = parseOle(b);
        streams = [...ole.streams.keys()];
        modules = vbaModules(ole.streams);
        // payloads are often stored outside the code: form controls, document text, custom properties
        for (const [name, data] of ole.streams) {
            if (/(^|\/)(VBA\/|_VBA_PROJECT|PROJECT(wm)?$|dir$)/i.test(name) && !/\/(o|f)$/i.test(name)) continue;
            for (const str of longStrings(data)) embedded.push({ kind: "string in stream", where: name, value: str });
        }
    } else if (isZip(b)) {
        let entries;
        try { entries = await new ZipReader(new Uint8ArrayReader(new Uint8Array(b))).getEntries(); } catch { return null; }
        const names = entries.map(e => e.filename);
        if (!names.some(n => /^\[Content_Types\]\.xml$/i.test(n))) return null; // a zip, but not Office Open XML
        container = "Office Open XML (.docx/.docm/.xlsx/.xlsm/.pptm)";
        streams = names;
        for (const e of entries.filter(e => /vbaProject\.bin$/i.test(e.filename))) {
            const data = Buffer.from(await e.getData(new Uint8ArrayWriter()));
            try { modules.push(...vbaModules(parseOle(data).streams).map(m => ({ ...m, stream: `${e.filename}:${m.stream}` }))); } catch { /* damaged */ }
        }
        // external template / remote OLE links (template injection) and Excel 4.0 macro sheets
        for (const e of entries.filter(e => /\.rels$/i.test(e.filename))) {
            const x = Buffer.from(await e.getData(new Uint8ArrayWriter())).toString("utf8");
            for (const m of x.matchAll(/Target="([^"]+)"\s+TargetMode="External"/g)) embedded.push({ kind: "external link", where: e.filename, value: m[1].replace(/&amp;/g, "&") });
        }
        // Excel 4.0 (XLM) macro sheets: list the formulas cell by cell (binary .xlsb sheets are only named)
        for (const e of entries.filter(e => /macrosheets\/[^/]+\.(xml|bin)$/i.test(e.filename))) {
            if (/\.bin$/i.test(e.filename)) { embedded.push({ kind: "Excel 4.0 (XLM) macro sheet (binary, formulas not decoded)", where: e.filename, value: e.filename }); continue; }
            const x = Buffer.from(await e.getData(new Uint8ArrayWriter())).toString("utf8");
            const unx = t => t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
            const cells = [...x.matchAll(/<c\b[^>]*\br="([A-Z]+\d+)"[^>]*>([\s\S]*?)<\/c>/g)].map(m => {
                const f = m[2].match(/<f\b[^>]*>([\s\S]*?)<\/f>/), v = m[2].match(/<v>([\s\S]*?)<\/v>/);
                return f ? `${m[1]}: =${unx(f[1])}` : v ? `${m[1]}: ${unx(v[1])}` : null;
            }).filter(Boolean);
            embedded.push({ kind: "Excel 4.0 (XLM) macro sheet", where: e.filename, value: `${cells.length} cells`, cells });
        }
    } else return null;
    // strip the VB attribute header lines, keep the code readable
    const clean = m => m.code.replace(/^Attribute VB_[^\r\n]*\r?\n/gm, "");
    const text = modules.map(m => `' ===== VBA module: ${m.name} (${m.stream}) =====\r\n${clean(m)}`).join("\r\n\r\n")
        + (embedded.length ? `\r\n\r\n' ===== Links and macro sheets =====\r\n${embedded.map(e => `' ${e.kind}: ${e.value}  (${e.where})${e.cells ? "\r\n" + e.cells.join("\r\n") : ""}`).join("\r\n")}` : "");
    // long strings hidden in streams are decoded on their own as well (they are often the real payload)
    const payloads = embedded.filter(e => e.kind === "string in stream" && e.value.length >= 200).sort((a, b) => b.value.length - a.value.length).slice(0, 3).map(e => ({ where: e.where, text: e.value }));
    return { container, modules: modules.map(m => ({ name: m.name, stream: m.stream, size: m.code.length })), streams: streams.slice(0, 200),
        embedded: embedded.map(({ cells, ...e }) => ({ ...e, value: e.value.length > 300 ? e.value.slice(0, 300) + "…" : e.value })), payloads, text };
}
