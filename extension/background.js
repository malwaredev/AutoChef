// Talks to the local AutoChef server on behalf of the content script (no CORS / mixed-content issues).
const DEFAULT_SERVER = "http://127.0.0.1:8471";

async function server() {
    const { server } = await chrome.storage.sync.get({ server: DEFAULT_SERVER });
    return server.replace(/\/+$/, "");
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
    (async () => {
        const base = await server();
        try {
            if (msg.type === "analyze") {
                const r = await fetch(`${base}/api/analyze`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ inputBase64: msg.inputBase64, crib: msg.crib || "", keys: Array.isArray(msg.keys) ? msg.keys : [] }) });
                const data = await r.json();
                if (!r.ok || data.error) throw new Error(data.error || `HTTP ${r.status}`);
                // drop the decoded payloads, the page only needs recipes and previews
                data.results = data.results.map(x => ({ ...x, output: { ...x.output, base64: undefined } }));
                reply({ ok: true, data });
            } else if (msg.type === "ping") {
                const r = await fetch(`${base}/api/library`);
                reply({ ok: r.ok });
            }
        } catch (e) {
            reply({ ok: false, error: `Cannot reach AutoChef at ${base}. Start it with start.bat (Windows) or "npm start". (${e.message})` });
        }
    })();
    return true; // async reply
});
