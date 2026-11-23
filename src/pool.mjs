/**
 * A small pool of CyberChef worker threads with a per-job timeout.
 * A job that exceeds its timeout has its worker terminated and replaced,
 * so a pathological input can never freeze AutoChef.
 */
import { Worker } from "node:worker_threads";
import os from "node:os";

const WORKER_URL = new URL("./worker.mjs", import.meta.url);

class Slot {
    constructor() { this.spawn(); }
    spawn() {
        this.busy = false;
        this.pending = null;
        this.worker = new Worker(WORKER_URL);
        this.ready = new Promise(res => {
            const onMsg = m => { if (m && m.ready) { this.worker.off("message", onMsg); res(); } };
            this.worker.on("message", onMsg);
        });
        this.worker.on("message", m => {
            if (!m || m.ready || !this.pending || m.id !== this.pending.id) return;
            const p = this.pending; this.pending = null;
            clearTimeout(p.timer);
            this.worker.unref();
            p.resolve(m);
        });
        this.worker.on("error", err => this.fail(String(err && err.message || err)));
        this.worker.on("exit", () => this.fail("worker exited"));
        this.ready.then(() => { if (!this.pending) this.worker.unref(); });
    }
    fail(error) {
        if (!this.pending) return;
        const p = this.pending; this.pending = null;
        clearTimeout(p.timer);
        p.resolve({ id: p.id, ok: false, error });
    }
}

let nextId = 1;

export class ChefPool {
    constructor(size = Math.max(1, Math.min(4, os.cpus().length - 1))) {
        this.size = size;
        this.slots = [];
        this.queue = [];
    }

    _slots() {
        if (!this.slots.length) for (let i = 0; i < this.size; i++) this.slots.push(new Slot());
        return this.slots;
    }

    /** Run a job: {kind:"bake", input:ArrayBuffer, recipe} or {kind:"magic", input, ...}. */
    run(job, timeoutMs = 5000) {
        return new Promise(resolve => {
            this.queue.push({ job, timeoutMs, resolve });
            this._drain();
        });
    }

    async _drain() {
        for (const slot of this._slots()) {
            if (slot.busy || !this.queue.length) continue;
            const task = this.queue.shift();
            slot.busy = true;
            await slot.ready;
            const id = nextId++;
            const done = m => { slot.busy = false; task.resolve(m); this._drain(); };
            slot.pending = {
                id,
                resolve: done,
                timer: setTimeout(() => {
                    // hung operation: kill the worker and start a fresh one
                    const p = slot.pending; slot.pending = null;
                    slot.worker.removeAllListeners("exit");
                    slot.worker.terminate();
                    slot.spawn();
                    slot.busy = true;
                    slot.ready.then(() => { if (p) p.resolve({ id, ok: false, error: `timed out after ${task.timeoutMs} ms`, timeout: true }); });
                }, task.timeoutMs),
            };
            slot.worker.ref(); // keep the process alive while a job is running
            slot.worker.postMessage({ ...task.job, id });
        }
    }

    async close() {
        await Promise.all(this.slots.map(s => s.worker.terminate()));
        this.slots = [];
    }
}

let shared = null;
export function getPool() {
    if (!shared) shared = new ChefPool(Number(process.env.AUTOCHEF_WORKERS) || undefined);
    return shared;
}
