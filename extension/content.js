// AutoChef panel inside CyberChef (isolated content script, shadow DOM so CyberChef's styles are untouched).
(() => {
    if (window.__autochefLoaded) return;
    window.__autochefLoaded = true;

    const host = document.createElement("div");
    host.id = "autochef-root";
    document.documentElement.appendChild(host);
    const root = host.attachShadow({ mode: "open" });

    const DARK_THEMES = new Set(["dark", "solarizedDark", "geocities"]);
    root.innerHTML = `
<style>
  :host { all: initial; }
  .wrap { --bg:#ffffff; --panel:#f6f8fa; --text:#1f2328; --muted:#59636e; --border:#d0d7de; --accent:#0969da; --chip:#ddf4ff; --chipfg:#0a3069;
          --good:#1a7f37; --goodbg:#dafbe1; --warn:#9a6700; --warnbg:#fff8c5; --bad:#cf222e; --badbg:#ffebe9;
          font: 13px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--text); }
  .wrap.dark { --bg:#161b22; --panel:#0f1216; --text:#e6edf3; --muted:#8b98a8; --border:#2a323d; --accent:#4fa3ff; --chip:#1d3557; --chipfg:#cfe3ff;
          --good:#3fb950; --goodbg:#12361d; --warn:#d29922; --warnbg:#3a2c0b; --bad:#f85149; --badbg:#3d1518; }
  .fab { position: fixed; right: 18px; bottom: 18px; z-index: 2147483646; background: var(--accent); color: #fff; border: 0; border-radius: 999px;
         padding: 10px 16px; font: 600 13px system-ui, sans-serif; cursor: pointer; box-shadow: 0 4px 14px rgba(0,0,0,.25); }
  .panel { position: fixed; right: 18px; bottom: 66px; width: 440px; max-height: 70vh; overflow: auto; z-index: 2147483647; background: var(--bg);
           border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.3); padding: 12px; display: none; }
  .panel.open { display: block; }
  .head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .head b { font-size: 14px; } .sp { flex: 1; }
  button.s { background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 7px; padding: 4px 9px; cursor: pointer; font: inherit; }
  button.s:hover { border-color: var(--accent); }
  input { width: 100%; box-sizing: border-box; background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 7px; padding: 6px 8px; font: 12px ui-monospace, Consolas, monospace; }
  .res { border: 1px solid var(--border); border-radius: 9px; padding: 9px; margin-top: 8px; background: var(--panel); }
  .badge { font-size: 10px; font-weight: 700; padding: 1px 7px; border-radius: 999px; text-transform: uppercase; }
  .high { background: var(--goodbg); color: var(--good); } .medium { background: var(--warnbg); color: var(--warn); } .low { background: var(--badbg); color: var(--bad); }
  .chain { display: flex; flex-wrap: wrap; gap: 4px; margin: 6px 0; }
  .op { background: var(--chip); color: var(--chipfg); border-radius: 5px; padding: 1px 6px; font: 11px ui-monospace, Consolas, monospace; }
  .pre { white-space: pre-wrap; word-break: break-all; font: 11.5px ui-monospace, Consolas, monospace; max-height: 90px; overflow: auto; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 6px; margin: 6px 0; }
  .muted { color: var(--muted); } .err { background: var(--badbg); color: var(--bad); border-radius: 7px; padding: 8px; margin-top: 8px; }
  .lib { background: var(--warnbg); color: var(--warn); border-radius: 6px; padding: 4px 8px; margin: 6px 0; font-size: 12px; }
  .lib a { color: inherit; }
</style>
<div class="wrap">
  <button class="fab" id="fab" title="Find the CyberChef recipe for the current input">Auto recipe</button>
  <div class="panel" id="panel">
    <div class="head"><b>AutoChef</b><span class="muted" id="status"></span><span class="sp"></span><button class="s" id="run">Analyse input</button><button class="s" id="close" title="Close">✕</button></div>
    <input id="crib" placeholder="Crib: text you expect in the output (optional)">
    <input id="keys" placeholder="Key / password / IV (optional; several: separate with |)" autocomplete="off" spellcheck="false">
    <div id="out" class="muted" style="margin-top:8px">Click "Analyse input" to find recipes for the text or file currently in CyberChef's Input pane.</div>
  </div>
</div>`;

    const $ = s => root.getElementById(s);
    const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    let results = [];

    // follow CyberChef's own theme (Options → Theme), falling back to the OS setting
    function applyTheme(theme) {
        const dark = theme ? DARK_THEMES.has(theme) : matchMedia("(prefers-color-scheme: dark)").matches;
        root.querySelector(".wrap").classList.toggle("dark", dark);
    }
    const askPage = type => window.postMessage({ source: "autochef-cs", type }, "*");
    new MutationObserver(() => askPage("theme")).observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    askPage("theme");

    const pending = {};
    window.addEventListener("message", ev => {
        if (ev.source !== window || !ev.data || ev.data.source !== "autochef-page") return;
        if (ev.data.type === "theme") applyTheme(ev.data.theme);
        if (ev.data.type === "input" && pending.input) { pending.input(ev.data.inputBase64); pending.input = null; }
        if (ev.data.type === "applied") $("status").textContent = "recipe applied";
    });

    $("fab").addEventListener("click", () => { $("panel").classList.toggle("open"); });
    $("close").addEventListener("click", () => $("panel").classList.remove("open"));
    $("run").addEventListener("click", run);

    async function run() {
        $("status").textContent = "reading input…";
        const inputBase64 = await new Promise(res => { pending.input = res; askPage("getInput"); setTimeout(() => { if (pending.input) { pending.input = null; res(null); } }, 4000); });
        if (!inputBase64) { $("out").innerHTML = `<div class="err">The Input pane is empty (or CyberChef is still loading).</div>`; $("status").textContent = ""; return; }
        $("status").textContent = "searching…";
        const reply = await chrome.runtime.sendMessage({ type: "analyze", inputBase64, crib: $("crib").value, keys: $("keys").value.split("|").map(k => k.trim()).filter(Boolean) });
        if (!reply || !reply.ok) { $("out").innerHTML = `<div class="err">${esc(reply ? reply.error : "No reply from the extension")}</div>`; $("status").textContent = ""; return; }
        results = reply.data.results;
        $("status").textContent = `${results.length} found in ${(reply.data.stats.ms / 1000).toFixed(1)} s`;
        const al = reply.data.alerts || [];
        const alertHtml = al.length ? `<div class="lib">⚠ ${al.length} finding(s): ${al.slice(0, 12).map(a => `<b>${esc(a.type)}</b> ${esc(a.value)}`).join(" · ")}${al.length > 12 ? " …" : ""}</div>` : "";
        const enc = alertHtml + (reply.data.assessment ? `<div class="lib">🔒 ${esc(reply.data.assessment.message)}</div>` : reply.data.hash ? `<div class="lib"># ${esc(reply.data.hash.message)}</div>` : "");
        if (!results.length) { $("out").innerHTML = enc + `<div class="muted">No convincing decoding found. Try a crib.</div>`; return; }
        $("out").innerHTML = enc + results.map((r, i) => `<div class="res">
            <div><span class="badge ${r.confidence}" title="score ${r.score}/100">${r.confidence}</span> <b>${esc(r.summary)}</b></div>
            ${r.library ? `<div class="lib">Known pattern: ${esc(r.library.name)} · <a href="${esc(r.library.source.url)}" target="_blank" rel="noopener">source</a></div>` : ""}
            <div class="chain">${r.recipe.map(o => `<span class="op">${esc(o.op)}</span>`).join("")}</div>
            <div class="muted">${r.steps.map(s => esc(s.why)).join("<br>")}</div>
            <div class="pre">${esc((r.output.preview || r.output.hexPreview || "").slice(0, 600))}</div>
            <button class="s" data-i="${i}">Apply in CyberChef</button></div>`).join("");
        root.querySelectorAll("button[data-i]").forEach(b => b.addEventListener("click", () => {
            window.postMessage({ source: "autochef-cs", type: "apply", recipe: results[+b.dataset.i].recipe }, "*");
        }));
    }
})();
