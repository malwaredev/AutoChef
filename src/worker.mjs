/**
 * Worker thread: runs CyberChef recipes with CyberChef's own core "Chef" class –
 * the same engine the CyberChef web app uses, including flow-control operations
 * (Subsection, Fork, Merge, Register, Jump…). Running in a worker lets the main
 * process kill an operation that hangs on hostile input.
 */
import { parentPort } from "node:worker_threads";
import log from "loglevel";
log.setLevel("silent");

const base = new URL("../core/", import.meta.resolve("cyberchef")).href;
const { default: Chef } = await import(base + "Chef.mjs");
const { default: Magic } = await import(base + "lib/Magic.mjs");

// some operations print noise while failing
console.log = console.warn = console.error = console.debug = console.info = () => {};

parentPort.on("message", async msg => {
    const { id, kind } = msg;
    try {
        if (kind === "bake") {
            const r = await new Chef().bake(msg.input, msg.recipe, {});
            if (r.error) {
                parentPort.postMessage({ id, ok: false, error: String(r.error.displayStr || r.error).slice(0, 400) });
                return;
            }
            // CyberChef reports an OperationError (bad key, invalid input …) as the output text and stops early:
            // that is a failure, not a result
            if (typeof r.progress === "number" && r.progress < msg.recipe.length) {
                const txt = typeof r.result === "string" ? r.result : new TextDecoder().decode(new Uint8Array(r.result).subarray(0, 400));
                parentPort.postMessage({ id, ok: false, error: txt.slice(0, 400), failedStep: r.progress });
                return;
            }
            let out = r.result;
            if (typeof out === "string") out = new TextEncoder().encode(out).buffer; // HTML-presenting ops
            parentPort.postMessage({ id, ok: true, result: out, type: r.type }, [out]);
        } else if (kind === "magic") {
            const res = await new Magic(msg.input).speculativeExecution(msg.depth ?? 3, msg.extLang ?? false, msg.intensive ?? false, [], false, msg.crib ? new RegExp(msg.crib) : null);
            parentPort.postMessage({ id, ok: true, result: res.filter(r => r.recipe && r.recipe.length).slice(0, 8).map(r => r.recipe.map(o => ({ op: o.op, args: o.args }))) });
        } else if (kind === "ping") {
            parentPort.postMessage({ id, ok: true, result: "pong" });
        }
    } catch (e) {
        parentPort.postMessage({ id, ok: false, error: String((e && (e.displayStr || e.message)) || e).slice(0, 400) });
    }
});

parentPort.postMessage({ ready: true });
