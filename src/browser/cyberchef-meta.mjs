// Operation metadata for the browser edition (the Node API's help() is not available in a page):
// built from CyberChef's own OperationConfig.json.
import CONFIG from "cyberchef/src/core/config/OperationConfig.json";
const api = {
    help(name) {
        const key = Object.keys(CONFIG).find(k => k === name) || Object.keys(CONFIG).find(k => k.toLowerCase() === String(name).toLowerCase() || k.replace(/[^a-z0-9]/gi, "").toLowerCase() === String(name).toLowerCase());
        if (!key) return [];
        return [{ name: key, description: CONFIG[key].description, args: CONFIG[key].args.map(a => ({ ...a })) }];
    },
};
for (const name of Object.keys(CONFIG)) { const f = () => {}; f.opName = name; api[name] = f; }
export default api;
