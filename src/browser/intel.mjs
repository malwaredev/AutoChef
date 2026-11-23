/**
 * Reputation lookups in the browser edition. VirusTotal, AbuseIPDB and URLhaus do not accept
 * API calls from web pages (no CORS), so the page offers links that open their own sites;
 * Bitcoin addresses are still checked live on Blockstream, which allows browser calls.
 */
import { explorerLinks } from "../intel-links.mjs";
export { explorerLinks };
export function setIntelKeys() { return intelStatus(); }
export function intelStatus() { return { browser: true, services: { virustotal: false, abuseipdb: false, urlhaus: false, blockstream: true } }; }
const b64url = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export async function lookup(f) {
    const v = String(f.value || ""), t = f.type || "", e = encodeURIComponent(v);
    const isIp = /^IPv[46] address$/.test(t), isUrl = t === "URL", isDomain = t === "Domain", isHash = / hash$/.test(t);
    const links = [];
    if (isIp) links.push(`https://www.virustotal.com/gui/ip-address/${e}`, `https://www.abuseipdb.com/check/${e}`, `https://urlhaus.abuse.ch/browse.php?search=${e}`);
    if (isDomain) links.push(`https://www.virustotal.com/gui/domain/${e}`, `https://urlhaus.abuse.ch/browse.php?search=${e}`);
    if (isUrl) links.push(`https://www.virustotal.com/gui/url/${b64url(v)}`, `https://urlhaus.abuse.ch/browse.php?search=${e}`);
    if (isHash) links.push(`https://www.virustotal.com/gui/file/${e}`, `https://bazaar.abuse.ch/browse.php?search=${/^[0-9a-f]{64}$/i.test(v) ? "sha256" : "md5"}%3A${e}`);
    const results = [];
    if (/^Bitcoin \((P2PKH|P2SH|SegWit)/.test(t)) {
        try {
            const r = await fetch(`https://blockstream.info/api/address/${e}`, { signal: AbortSignal.timeout(20000) });
            const b = await r.json();
            const c = b.chain_stats || {};
            results.push({ service: "Blockstream", ok: r.ok, verdict: c.tx_count ? "active" : "unused", details: `${c.tx_count || 0} transactions, ${(c.funded_txo_sum || 0) / 1e8} BTC received, ${((c.funded_txo_sum || 0) - (c.spent_txo_sum || 0)) / 1e8} BTC balance`, link: `https://blockstream.info/address/${e}` });
        } catch (err) { results.push({ service: "Blockstream", ok: false, error: err.message }); }
    }
    const all = [...links, ...(f.category === "crypto" ? explorerLinks(t, v) : [])];
    return { results, links: all, note: isIp || isUrl || isDomain || isHash ? "Browser edition: reputation services can't be queried from a web page. The links open each service's own site with this value." : undefined };
}
