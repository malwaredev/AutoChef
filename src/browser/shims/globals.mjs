// Node globals for the browser build: Buffer (with Node's "base64url" encoding added) and process.
import { Buffer } from "buffer/";
import process from "process/browser.js";

const toStd = s => { s = String(s).replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, ""); return s + "=".repeat((4 - s.length % 4) % 4); };
const origFrom = Buffer.from, origToString = Buffer.prototype.toString;
Buffer.from = function (v, enc, len) { return typeof v === "string" && enc === "base64url" ? origFrom.call(Buffer, toStd(v), "base64") : origFrom.call(Buffer, v, enc, len); };
Buffer.prototype.toString = function (enc, start, end) { return enc === "base64url" ? origToString.call(this, "base64", start, end).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : origToString.call(this, enc, start, end); };
const origIsEnc = Buffer.isEncoding; Buffer.isEncoding = e => e === "base64url" || origIsEnc(e);
process.env = process.env || {};
globalThis.Buffer ??= Buffer;
globalThis.process ??= process;
export { Buffer, process };
