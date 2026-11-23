/**
 * Optional reputation lookups for findings. OFF by default: nothing is sent anywhere until you
 * click "Look up" (or call lookup()), and only the single indicator you look up is sent.
 *
 *   VirusTotal (API v3)    URLs, domains, IPs, file hashes        key: VT_API_KEY
 *   AbuseIPDB (API v2)     IP addresses                           key: ABUSEIPDB_API_KEY
 *   URLhaus (abuse.ch)     URLs, hosts, payload hashes            key: ABUSECH_AUTH_KEY
 *   Blockstream Esplora    Bitcoin addresses (no key needed)
 *
 * Keys typed in the web UI are kept in memory only. Explorer links for every wallet type are
 * provided without any request.
 */
import { explorerLinks } from "./intel-links.mjs";
export { explorerLinks };

const keys = { virustotal: process.env.VT_API_KEY || null, abuseipdb: process.env.ABUSEIPDB_API_KEY || null, urlhaus: process.env.ABUSECH_AUTH_KEY || null };

export function setIntelKeys(k = {}) {
    for (const s of Object.keys(keys)) if (s in k) keys[s] = k[s] ? String(k[s]).trim() : null;
    return intelStatus();
}
export function intelStatus() {
    return { services: { virustotal: !!keys.virustotal, abuseipdb: !!keys.abuseipdb, urlhaus: !!keys.urlhaus, blockstream: true } };
}

const T = 20000;
async function getJson(url, init = {}) {
    const res = await fetch(url, { ...init, signal: AbortSignal.timeout(T) });
    const body = await res.json().catch(() => ({}));
    return { status: res.status, ok: res.ok, body };
}
const b64url = s => Buffer.from(s).toString("base64url");

/**
 * Look up one finding {type, value, category}. Returns {results:[{service, ok, verdict, details, link, error}]}.
 * Each service is asked only if it can answer for that type and (where needed) has a key.
 */
export async function lookup(f) {
    const out = [];
    const v = String(f.value || "");
    const t = f.type || "";
    const isIp = /^IPv[46] address$/.test(t), isUrl = t === "URL", isDomain = t === "Domain", isHash = / hash$/.test(t) && /^[0-9a-f]+$/i.test(v);
    const guard = async (service, fn) => { try { out.push({ service, ...(await fn()) }); } catch (e) { out.push({ service, ok: false, error: e.name === "TimeoutError" ? "timed out" : e.message }); } };

    if (keys.virustotal && (isIp || isUrl || isDomain || isHash)) await guard("VirusTotal", async () => {
        const path = isIp ? `ip_addresses/${encodeURIComponent(v)}` : isDomain ? `domains/${encodeURIComponent(v)}` : isUrl ? `urls/${b64url(v)}` : `files/${v.toLowerCase()}`;
        const link = isIp ? `https://www.virustotal.com/gui/ip-address/${v}` : isDomain ? `https://www.virustotal.com/gui/domain/${v}` : isUrl ? `https://www.virustotal.com/gui/url/${b64url(v)}` : `https://www.virustotal.com/gui/file/${v}`;
        const r = await getJson(`https://www.virustotal.com/api/v3/${path}`, { headers: { "x-apikey": keys.virustotal } });
        if (r.status === 404) return { ok: true, verdict: "unknown", details: "Not in VirusTotal", link };
        if (!r.ok) return { ok: false, error: `HTTP ${r.status}: ${r.body?.error?.message || ""}`, link };
        const st = r.body?.data?.attributes?.last_analysis_stats || {};
        const mal = (st.malicious || 0), sus = (st.suspicious || 0), total = Object.values(st).reduce((a, x) => a + (x || 0), 0);
        return { ok: true, verdict: mal ? "malicious" : sus ? "suspicious" : "clean", details: `${mal} malicious, ${sus} suspicious of ${total} engines`, link };
    });
    if (keys.abuseipdb && isIp) await guard("AbuseIPDB", async () => {
        const r = await getJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(v)}&maxAgeInDays=90`, { headers: { Key: keys.abuseipdb, Accept: "application/json" } });
        if (!r.ok) return { ok: false, error: `HTTP ${r.status}: ${r.body?.errors?.[0]?.detail || ""}` };
        const d = r.body.data || {};
        return { ok: true, verdict: d.abuseConfidenceScore >= 50 ? "malicious" : d.abuseConfidenceScore > 0 ? "suspicious" : "clean", details: `abuse confidence ${d.abuseConfidenceScore}%, ${d.totalReports || 0} reports, ${d.countryCode || "?"}, ${d.isp || ""}`, link: `https://www.abuseipdb.com/check/${v}` };
    });
    if (keys.urlhaus && (isUrl || isDomain || isIp || (isHash && (v.length === 32 || v.length === 64)))) await guard("URLhaus", async () => {
        const [ep, field] = isUrl ? ["url", "url"] : isHash ? ["payload", v.length === 32 ? "md5_hash" : "sha256_hash"] : ["host", "host"];
        const r = await getJson(`https://urlhaus-api.abuse.ch/v1/${ep}/`, { method: "POST", headers: { "Auth-Key": keys.urlhaus, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ [field]: v }) });
        if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
        const b = r.body;
        if (b.query_status === "no_results") return { ok: true, verdict: "unknown", details: "Not in URLhaus" };
        if (b.query_status !== "ok") return { ok: false, error: b.query_status };
        const n = b.url_count ?? b.urls?.length ?? 0;
        return { ok: true, verdict: "malicious", details: isUrl ? `${b.threat || "malware"} URL, status ${b.url_status}, tags ${(b.tags || []).join(", ")}` : `${n} malware URL(s) on record${b.signature ? ", " + b.signature : ""}`, link: b.urlhaus_reference || "" };
    });
    if (/^Bitcoin \((P2PKH|P2SH|SegWit)/.test(t)) await guard("Blockstream", async () => {
        const r = await getJson(`https://blockstream.info/api/address/${encodeURIComponent(v)}`);
        if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
        const c = r.body.chain_stats || {};
        return { ok: true, verdict: c.tx_count ? "active" : "unused", details: `${c.tx_count || 0} transactions, ${(c.funded_txo_sum || 0) / 1e8} BTC received, ${((c.funded_txo_sum || 0) - (c.spent_txo_sum || 0)) / 1e8} BTC balance`, link: `https://blockstream.info/address/${v}` };
    });
    const links = f.category === "crypto" ? explorerLinks(t, v) : [];
    if (!out.length && !links.length) return { results: [], note: "No configured service can look this type up. Add a VirusTotal, AbuseIPDB or URLhaus key in Threat-intel settings." };
    return { results: out, links };
}
