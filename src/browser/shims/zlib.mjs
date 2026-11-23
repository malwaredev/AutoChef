// node:zlib for the browser (browserify-zlib / pako) plus the `constants` object Node has.
import z from "browserify-zlib";
export const constants = { Z_NO_FLUSH: 0, Z_PARTIAL_FLUSH: 1, Z_SYNC_FLUSH: 2, Z_FULL_FLUSH: 3, Z_FINISH: 4 };
const strip = o => { if (!o) return o; const { maxOutputLength, ...rest } = o; return rest; };
export const inflateRawSync = (b, o) => z.inflateRawSync(b, strip(o));
export const inflateSync = (b, o) => z.inflateSync(b, strip(o));
export const gunzipSync = (b, o) => z.gunzipSync(b, strip(o));
export const unzipSync = (b, o) => z.unzipSync(b, strip(o));
export const deflateRawSync = (b, o) => z.deflateRawSync(b, o);
export const deflateSync = (b, o) => z.deflateSync(b, o);
export const gzipSync = (b, o) => z.gzipSync(b, o);
export default { constants, inflateRawSync, inflateSync, gunzipSync, unzipSync, deflateRawSync, deflateSync, gzipSync };
