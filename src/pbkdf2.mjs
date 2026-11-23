/**
 * PBKDF2 that is fast everywhere: Node's native implementation locally, the Web Crypto API in the
 * browser edition (the pure-JavaScript fallback there is ~100× slower: seconds per key).
 */
import crypto from "node:crypto";

const HASH = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
const subtle = typeof window !== "undefined" && globalThis.crypto && globalThis.crypto.subtle;

export async function pbkdf2(password, salt, iterations, length, hash) {
    if (subtle && HASH[hash]) {
        const key = await subtle.importKey("raw", new Uint8Array(password), "PBKDF2", false, ["deriveBits"]);
        const bits = await subtle.deriveBits({ name: "PBKDF2", hash: HASH[hash], salt: new Uint8Array(salt), iterations }, key, length * 8);
        return Buffer.from(bits);
    }
    return crypto.pbkdf2Sync(password, salt, iterations, length, hash);
}
