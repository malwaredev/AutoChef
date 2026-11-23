/**
 * Browser version of src/pool.mjs: CyberChef runs in Web Workers (cc-worker.js); a job that
 * exceeds its timeout has its worker terminated and replaced, exactly like the Node pool.
 */
const WORKER_URL = new URL("./cc-worker.js", import.meta.url);
let nextId = 1;

class Slot {
    constructor() { this.spawn(); }
    spawn() {
        this.busy = false; this.pending = null;
        this.worker = new Worker(WORKER_URL);
        this.isReady = false;
        this.ready = new Promise(res => { const f = e => { if (e.data && e.data.ready) { this.worker.removeEventListener("message", f); this.isReady = true; res(); } }; this.worker.addEventListener("message", f); });
        this.worker.addEventListener("message", e => {
            const m = e.data;
            if (m && this.softBusy && m.id === this.softBusy) { this.softBusy = null; this.busy = false; this.onFree?.(); return; } // late Magic answer
            if (!m || m.ready || !this.pending || m.id !== this.pending.id) return;
            const p = this.pending; this.pending = null; clearTimeout(p.timer); p.resolve(m);
        });
        this.worker.addEventListener("error", e => { e.preventDefault?.(); this.fail(String(e.message || "worker error")); });
    }
    fail(error) { if (!this.pending) return; const p = this.pending; this.pending = null; clearTimeout(p.timer); p.resolve({ id: p.id, ok: false, error }); }
}

export class ChefPool {
    // at least two workers: CyberChef Magic can hold one for seconds while the other keeps baking
    constructor(size = Math.max(2, Math.min(4, (globalThis.navigator?.hardwareConcurrency || 2) - 1))) { this.size = size; this.slots = []; this.queue = []; }
    _slots() { if (!this.slots.length) for (let i = 0; i < this.size; i++) { const sl = new Slot(); sl.onFree = () => this._drain(); this.slots.push(sl); } return this.slots; }
    warm() {
        this._slots();
        this.magicSlot ||= new Slot();
        this.magicSlot.ready.then(() => { this.magicSlot.isReady = true; });
        return Promise.all(this.slots.map(s => s.ready));
    }
    run(job, timeoutMs = 5000) {
        if (job.kind === "magic") return this._magic(job, timeoutMs);
        return new Promise(resolve => { this.queue.push({ job, timeoutMs, resolve }); this._drain(); });
    }
    /**
     * CyberChef Magic gets its own worker: it only seeds the search, so when that worker is not
     * ready (or still restarting after a timeout) the search goes on without it instead of waiting,
     * and killing a runaway Magic never delays the recipe bakes.
     */
    _magic(job, timeoutMs) {
        const m = this.magicSlot ||= new Slot();
        if (!m.isReady || m.busy) return Promise.resolve({ ok: false, error: "magic worker not ready" });
        m.busy = true;
        const id = nextId++;
        return new Promise(resolve => {
            m.pending = { id, resolve: r => { m.busy = false; resolve(r); }, timer: setTimeout(() => {
                const p = m.pending; m.pending = null;
                m.worker.terminate(); m.spawn(); m.isReady = false; m.ready.then(() => { m.isReady = true; });
                p.resolve({ id, ok: false, error: "magic timed out", timeout: true });
            }, timeoutMs) };
            m.worker.postMessage({ ...job, id }, job.input instanceof ArrayBuffer ? [job.input] : []);
        });
    }
    async _drain() {
        for (const slot of this._slots()) {
            if (slot.busy || !this.queue.length) continue;
            const task = this.queue.shift();
            slot.busy = true;
            await slot.ready;
            const id = nextId++;
            const done = m => { if (slot.softBusy === id) return; slot.busy = false; task.resolve(m); this._drain(); };
            slot.pending = { id, resolve: done, timer: setTimeout(() => {
                const p = slot.pending; slot.pending = null;
                // (a timed-out job is never left running: CyberChef Magic on random data can use
                // gigabytes and would take the whole tab down)
                slot.worker.terminate(); slot.spawn(); slot.busy = true;
                slot.ready.then(() => { if (p) p.resolve({ id, ok: false, error: `timed out after ${task.timeoutMs} ms`, timeout: true }); });
            }, task.timeoutMs) };
            const transfer = task.job.input instanceof ArrayBuffer ? [task.job.input] : [];
            slot.worker.postMessage({ ...task.job, id }, transfer);
        }
    }
    async close() { this.slots.forEach(s => s.worker.terminate()); this.slots = []; }
}
let shared = null;
export function getPool() { if (!shared) shared = new ChefPool(); return shared; }
