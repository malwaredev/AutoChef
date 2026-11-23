/**
 * Helpers to turn a recipe into CyberChef's own formats (pretty recipe string,
 * shareable URL) so a result can be opened and edited in CyberChef directly.
 */

export const CYBERCHEF_URL = "https://gchq.github.io/CyberChef/";

/** Same algorithm as CyberChef's Utils.generatePrettyRecipe */
export function prettyRecipe(ops) {
    return ops.map(o => {
        const args = JSON.stringify(o.args)
            .slice(1, -1)
            .replace(/'/g, "\\'")
            .replace(/"((?:[^"\\]|\\.)*)"/g, "'$1'")
            .replace(/\\"/g, '"');
        return `${o.op.replace(/ /g, "_")}(${args})`;
    }).join("");
}

/** Same algorithm as CyberChef's Utils.encodeURIFragment */
function encodeURIFragment(str) {
    const LEGAL = { "%2D": "-", "%2E": ".", "%5F": "_", "%7E": "~", "%21": "!", "%24": "$", "%27": "'", "%28": "(", "%29": ")", "%2A": "*", "%2C": ",", "%3B": ";", "%3A": ":", "%40": "@", "%2F": "/", "%3F": "?" };
    return encodeURIComponent(str).replace(/%[0-9A-F]{2}/g, m => LEGAL[m] || m);
}

/**
 * Build a link that opens CyberChef with this recipe (and the input, if small enough).
 * @param {object[]} ops
 * @param {Uint8Array} [inputBytes]
 * @param {string} [base]
 */
export function cyberChefUrl(ops, inputBytes, base = CYBERCHEF_URL) {
    const parts = [`recipe=${encodeURIFragment(prettyRecipe(ops))}`];
    if (inputBytes && inputBytes.length && inputBytes.length <= 48 * 1024) {
        const b64 = Buffer.from(inputBytes).toString("base64").replace(/=+$/, "");
        parts.push(`input=${encodeURIFragment(b64)}`);
    }
    return `${base}#${parts.join("&")}`;
}
