// Runs in CyberChef's own page context: reads the current input and applies recipes using CyberChef's app API.
(() => {
    const toB64 = buf => {
        const u = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new TextEncoder().encode(String(buf));
        let s = "";
        for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
        return btoa(s);
    };
    window.addEventListener("message", async ev => {
        if (ev.source !== window || !ev.data || ev.data.source !== "autochef-cs") return;
        const app = window.app;
        if (!app || !app.manager) return;
        if (ev.data.type === "getInput") {
            let value;
            try {
                const num = app.manager.tabs.getActiveTab("input");
                value = await app.manager.input.getInputValue(num);
            } catch {
                value = app.manager.input.getInput();
            }
            window.postMessage({ source: "autochef-page", type: "input", inputBase64: toB64(value ?? "") }, "*");
        }
        if (ev.data.type === "apply") {
            app.setRecipeConfig(ev.data.recipe);
            app.autoBake();
            window.postMessage({ source: "autochef-page", type: "applied" }, "*");
        }
        if (ev.data.type === "theme") {
            window.postMessage({ source: "autochef-page", type: "theme", theme: document.documentElement.className || (app.options && app.options.theme) || "classic" }, "*");
        }
    });
})();
