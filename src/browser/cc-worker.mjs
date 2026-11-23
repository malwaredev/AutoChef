/**
 * Browser Web Worker: runs CyberChef recipes with CyberChef's core Chef and Magic classes,
 * the same engine as the CyberChef web app. Mirrors src/worker.mjs (Node worker_threads).
 */
import Chef from "cyberchef/src/core/Chef.mjs";
import Magic from "cyberchef/src/core/lib/Magic.mjs";
import OpModules from "cyberchef/src/core/config/modules/OpModules.mjs";
import log from "loglevel";
log.setLevel("silent");
self.log = log;
// what CyberChef's own ChefWorker provides: every module is already in this bundle
self.OpModules = OpModules;
self.loadRequiredModules = () => {};
self.sendStatusMessage = () => {};
self.setOption = () => {};
self.sendProgressMessage = () => {};
self.setRegisters = () => {};

self.onmessage = async e => {
    const msg = e.data, { id, kind } = msg;
    try {
        if (kind === "bake") {
            const r = await new Chef().bake(msg.input, msg.recipe, {});
            if (r.error) { self.postMessage({ id, ok: false, error: String(r.error.displayStr || r.error).slice(0, 400) }); return; }
            if (typeof r.progress === "number" && r.progress < msg.recipe.length) {
                const txt = typeof r.result === "string" ? r.result : new TextDecoder().decode(new Uint8Array(r.result).subarray(0, 400));
                self.postMessage({ id, ok: false, error: txt.slice(0, 400), failedStep: r.progress });
                return;
            }
            let out = r.result;
            if (typeof out === "string") out = new TextEncoder().encode(out).buffer;
            self.postMessage({ id, ok: true, result: out, type: r.type }, [out]);
        } else if (kind === "magic") {
            const res = await new Magic(msg.input).speculativeExecution(msg.depth ?? 3, false, msg.intensive ?? false, [], false, msg.crib ? new RegExp(msg.crib) : null);
            self.postMessage({ id, ok: true, result: res.filter(r => r.recipe && r.recipe.length).slice(0, 8).map(r => r.recipe.map(o => ({ op: o.op, args: o.args }))) });
        } else if (kind === "ping") self.postMessage({ id, ok: true, result: "pong" });
    } catch (err) {
        self.postMessage({ id, ok: false, error: String((err && (err.displayStr || err.message)) || err).slice(0, 400) });
    }
};
self.postMessage({ ready: true });
