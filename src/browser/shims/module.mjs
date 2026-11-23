// createRequire() for the browser build: the few CommonJS packages AutoChef loads that way are bundled here.
import LZString from "lz-string";
import * as phone from "libphonenumber-js/max";
const MODS = { "lz-string": LZString, "libphonenumber-js/max": phone };
export function createRequire() { return name => { if (name in MODS) return MODS[name]; throw new Error(`${name} is not bundled in the browser edition`); }; }
export default { createRequire };
