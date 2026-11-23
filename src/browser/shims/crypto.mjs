// node:crypto for the browser: crypto-browserify (hashes, HMAC, PBKDF2, AES and DES in all modes)
// plus randomUUID / getRandomValues from the Web Crypto API.
import cb from "crypto-browserify";
// Node accepts iv = null for ECB; the browser implementation needs an empty buffer
export const createDecipheriv = (a, k, iv, o) => cb.createDecipheriv(a, k, iv ?? Buffer.alloc(0), o);
export const createCipheriv = (a, k, iv, o) => cb.createCipheriv(a, k, iv ?? Buffer.alloc(0), o);
export const createHash = cb.createHash, createHmac = cb.createHmac, pbkdf2Sync = cb.pbkdf2Sync, getCiphers = cb.getCiphers;
export const randomBytes = n => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return Buffer.from(b); };
export const randomUUID = () => globalThis.crypto.randomUUID();
export default { ...cb, createHash, createHmac, pbkdf2Sync, createDecipheriv, createCipheriv, getCiphers, randomBytes, randomUUID };
