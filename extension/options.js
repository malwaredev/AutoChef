const el = id => document.getElementById(id);
chrome.storage.sync.get({ server: "http://127.0.0.1:8471" }, v => { el("server").value = v.server; });
el("save").addEventListener("click", () => {
    const v = el("server").value.trim();
    if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\/?$/.test(v)) { el("msg").textContent = "Only a local address (127.0.0.1 / localhost) is allowed."; return; }
    chrome.storage.sync.set({ server: v }, () => { el("msg").textContent = "Saved."; });
});
