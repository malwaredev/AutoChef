/**
 * Optional AI assistance (off unless you give it an API key, or a local model server).
 *
 * Works with any provider: Anthropic (Claude), OpenAI, Google Gemini, Mistral, Groq, OpenRouter,
 * DeepSeek, xAI, Together, a local Ollama or LM Studio, or ANY other server that speaks the
 * OpenAI chat-completions API (give its base URL). Model lists are read from the provider itself
 * (GET /models), so no model name is hard-coded.
 *
 * The model only PROPOSES recipes. Every proposal is executed by CyberChef and scored
 * exactly like AutoChef's own candidates, so a wrong or invented suggestion simply scores
 * low – the AI can never put text in the output that CyberChef did not produce.
 *
 * Privacy: when used, an excerpt of the sample (first 6 KB, as text/hex) and AutoChef's
 * current best attempts are sent to the provider you chose. Keep it off for sensitive material,
 * or use a local model (Ollama / LM Studio).
 *
 * Environment (optional): AUTOCHEF_AI_PROVIDER, AUTOCHEF_AI_MODEL, AUTOCHEF_AI_BASE_URL and the
 * provider's usual key variable (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, …).
 */
import { bakeAndScore } from "./search.mjs";

export const PROVIDERS = {
    anthropic: { name: "Anthropic (Claude)", kind: "anthropic", base: "https://api.anthropic.com/v1", env: "ANTHROPIC_API_KEY", keyPrefix: "sk-ant-" },
    openai: { name: "OpenAI", kind: "openai", base: "https://api.openai.com/v1", env: "OPENAI_API_KEY", keyPrefix: "sk-" },
    gemini: { name: "Google Gemini", kind: "openai", base: "https://generativelanguage.googleapis.com/v1beta/openai", env: "GEMINI_API_KEY", keyPrefix: "AIza" },
    mistral: { name: "Mistral", kind: "openai", base: "https://api.mistral.ai/v1", env: "MISTRAL_API_KEY" },
    groq: { name: "Groq", kind: "openai", base: "https://api.groq.com/openai/v1", env: "GROQ_API_KEY", keyPrefix: "gsk_" },
    openrouter: { name: "OpenRouter", kind: "openai", base: "https://openrouter.ai/api/v1", env: "OPENROUTER_API_KEY", keyPrefix: "sk-or-" },
    deepseek: { name: "DeepSeek", kind: "openai", base: "https://api.deepseek.com/v1", env: "DEEPSEEK_API_KEY" },
    xai: { name: "xAI (Grok)", kind: "openai", base: "https://api.x.ai/v1", env: "XAI_API_KEY", keyPrefix: "xai-" },
    together: { name: "Together AI", kind: "openai", base: "https://api.together.xyz/v1", env: "TOGETHER_API_KEY" },
    ollama: { name: "Ollama (local, no key)", kind: "openai", base: "http://127.0.0.1:11434/v1", noKey: true },
    lmstudio: { name: "LM Studio (local, no key)", kind: "openai", base: "http://127.0.0.1:1234/v1", noKey: true },
    custom: { name: "Other OpenAI-compatible API (base URL)", kind: "openai", base: "", env: "AUTOCHEF_AI_KEY" },
};

/** Guess the provider from the shape of a key (the user can always choose explicitly). */
export function detectProvider(key) {
    const k = String(key || "");
    for (const id of ["anthropic", "openrouter", "groq", "xai", "gemini"]) if (k.startsWith(PROVIDERS[id].keyPrefix)) return id;
    if (k.startsWith("sk-")) return "openai";
    return null;
}

// settings kept in memory only, never written to disk
const ENV = (typeof process !== "undefined" && process.env) || {};
const cfg = { provider: ENV.AUTOCHEF_AI_PROVIDER || null, model: ENV.AUTOCHEF_AI_MODEL || null, baseUrl: ENV.AUTOCHEF_AI_BASE_URL || null, key: null };
if (!cfg.provider) cfg.provider = Object.keys(PROVIDERS).find(id => PROVIDERS[id].env && ENV[PROVIDERS[id].env]) || null;

function current() {
    const id = cfg.provider;
    if (!id || !PROVIDERS[id]) return null;
    const p = PROVIDERS[id];
    const key = cfg.key || (p.env ? ENV[p.env] : null) || null;
    const base = (id === "custom" || cfg.baseUrl ? cfg.baseUrl || p.base : p.base || "").replace(/\/+$/, "");
    return { id, ...p, key, base };
}

/** {provider, key?, model?, baseUrl?}: any field left out keeps its value; key:null forgets the key */
export function configureAi(c = {}) {
    if (c.provider !== undefined && c.provider !== cfg.provider) { cfg.provider = PROVIDERS[c.provider] ? c.provider : null; if (c.key === undefined) cfg.key = null; cfg.model = null; }
    if (c.key !== undefined) cfg.key = c.key ? String(c.key).trim() : null;
    if (c.key && c.provider === undefined && !cfg.provider) cfg.provider = detectProvider(c.key);
    if (c.model !== undefined) cfg.model = c.model ? String(c.model).trim() : null;
    if (c.baseUrl !== undefined) cfg.baseUrl = c.baseUrl ? String(c.baseUrl).trim() : null;
    return aiStatus();
}
/** kept for older callers */
export function setApiKey(k) { configureAi({ key: k || null, ...(k && !cfg.provider ? { provider: detectProvider(k) || "anthropic" } : {}) }); }

export function aiAvailable() { const c = current(); return !!(c && (c.key || c.noKey) && c.base && cfg.model); }
export function aiStatus() {
    const c = current();
    return { available: aiAvailable(), provider: c ? c.id : null, providerName: c ? c.name : null, model: cfg.model, baseUrl: c ? c.base : null, hasKey: !!(c && c.key), noKey: !!(c && c.noKey),
        providers: Object.entries(PROVIDERS).map(([id, p]) => ({ id, name: p.name, base: p.base, noKey: !!p.noKey })) };
}
export const DEFAULT_MODEL = null;

function headers(c) {
    // in the browser edition the request goes straight from the page to the provider
    const inBrowser = typeof window !== "undefined" && typeof document !== "undefined";
    if (c.kind === "anthropic") return { "content-type": "application/json", "x-api-key": c.key, "anthropic-version": "2023-06-01", ...(inBrowser ? { "anthropic-dangerous-direct-browser-access": "true" } : {}) };
    const h = { "content-type": "application/json" };
    if (c.key) h.authorization = `Bearer ${c.key}`;
    if (c.id === "openrouter") { h["HTTP-Referer"] = "https://github.com/"; h["X-Title"] = "AutoChef"; }
    return h;
}

/** The provider's own model list */
export async function listModels() {
    const c = current();
    if (!c || !c.base) return { ok: false, error: "Choose a provider (and a base URL for 'Other')." };
    if (!c.key && !c.noKey) return { ok: false, error: "Enter the API key first." };
    let res;
    try { res = await fetch(`${c.base}/models`, { headers: headers(c), signal: AbortSignal.timeout(15000) }); }
    catch (e) { return { ok: false, error: `Could not reach ${c.base}: ${e.message}` }; }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: `${c.name} error ${res.status}: ${body?.error?.message || res.statusText}` };
    const list = (body.data || body.models || []).map(m => ({ id: String(m.id || m.name || "").replace(/^models\//, ""), name: m.display_name || m.name || m.id })).filter(m => m.id);
    return { ok: true, models: list };
}

/** Send one prompt, get the text answer */
async function chat(c, prompt) {
    const url = c.kind === "anthropic" ? `${c.base}/messages` : `${c.base}/chat/completions`;
    const body = c.kind === "anthropic"
        ? { model: cfg.model, max_tokens: 2000, messages: [{ role: "user", content: prompt }] }
        : { model: cfg.model, max_tokens: 2000, temperature: 0.2, messages: [{ role: "system", content: "You are a careful malware-analysis assistant. Answer with JSON only." }, { role: "user", content: prompt }] };
    let res;
    try { res = await fetch(url, { method: "POST", headers: headers(c), body: JSON.stringify(body), signal: AbortSignal.timeout(120000) }); }
    catch (e) { return { error: `Could not reach ${c.name} (${c.base}): ${e.message}` }; }
    const j = await res.json().catch(() => ({}));
    if (!res.ok) return { error: `${c.name} API error ${res.status}: ${j?.error?.message || res.statusText}` };
    if (c.kind === "anthropic") return { text: (j.content || []).filter(x => x.type === "text").map(x => x.text).join("\n") };
    const m = j.choices?.[0]?.message;
    return { text: typeof m?.content === "string" ? m.content : Array.isArray(m?.content) ? m.content.map(x => x.text || "").join("\n") : "" };
}

const OPS_HINT = ["From Base64", "From Base32", "From Base85", "From Hex", "From Decimal", "From Charcode", "From Octal", "From Binary",
    "URL Decode", "From HTML Entity", "Unescape string", "Unescape Unicode Characters", "Decode text", "Remove null bytes",
    "Gunzip", "Raw Inflate", "Zlib Inflate", "Bzip2 Decompress", "LZMA Decompress", "XOR", "RC4", "AES Decrypt", "DES Decrypt",
    "Triple DES Decrypt", "ROT13", "ROT47", "Reverse", "Find / Replace", "Regular expression", "Subsection", "Merge", "Fork",
    "Drop bytes", "Take bytes", "Strings", "Microsoft Script Decoder", "Label", "Jump", "Conditional Jump", "Substitute", "Vigenère Decode"];

function excerpt(bytes) {
    const n = Math.min(bytes.length, 6144);
    const s = Buffer.from(bytes.subarray(0, n)).toString("latin1");
    const printable = [...s].filter(c => c >= " " && c <= "~" || c === "\n" || c === "\r" || c === "\t").length / Math.max(1, n);
    return printable > 0.85 ? { kind: "text", body: s } : { kind: "hex", body: Buffer.from(bytes.subarray(0, 1024)).toString("hex") };
}

/**
 * Ask the model for up to `max` recipes, verify each with CyberChef, return them scored.
 * @param {Uint8Array} input
 * @param {object[]} currentResults  AutoChef's results (to show the model what was tried)
 */
export async function aiSuggest(input, currentResults = [], { max = 3 } = {}) {
    const c = current();
    if (!aiAvailable()) return { ok: false, error: "The AI assistant is not set up: choose a provider, enter its API key (not needed for local models) and pick a model in AI settings." };
    const ex = excerpt(input);
    const tried = currentResults.slice(0, 3).map((r, i) => `${i + 1}. ${r.recipe.map(o => o.op).join(" > ")}  (score ${r.score}) -> ${(r.output.preview || r.output.hexPreview || "").slice(0, 300).replace(/\s+/g, " ")}`).join("\n") || "(nothing convincing yet)";
    const prompt = `You are helping a malware analyst decode an obfuscated sample with CyberChef.
Sample size: ${input.length} bytes. Excerpt (${ex.kind}, first part only):
<<<
${ex.body}
>>>

Recipes already tried by an automatic search:
${tried}

Propose up to ${max} DIFFERENT CyberChef recipes that could decode it further. Use only real CyberChef operation names, for example: ${OPS_HINT.join(", ")}.
Arguments must be given in CyberChef's own order and format (as in CyberChef's "Save recipe" JSON), e.g.
[{"op":"From Base64","args":["A-Za-z0-9+/=",true,false]},{"op":"XOR","args":[{"option":"Hex","string":"23"},"Standard",false]}]
If the script itself contains keys, IVs or XOR values, use them.

Answer with JSON only, no prose: {"suggestions":[{"why":"one sentence","recipe":[...]}]}`;

    const r = await chat(c, prompt);
    if (r.error) return { ok: false, error: r.error };
    const text = r.text || "";
    const json = parseJson(text);
    if (!json || !Array.isArray(json.suggestions)) return { ok: false, error: "The model's answer was not valid JSON", raw: text.slice(0, 2000) };

    // verify every suggestion with CyberChef
    const verified = [];
    for (const sug of json.suggestions.slice(0, max)) {
        if (!Array.isArray(sug.recipe) || !sug.recipe.every(o => o && typeof o.op === "string" && Array.isArray(o.args ?? []))) continue;
        const recipe = sug.recipe.map(o => ({ op: o.op, args: o.args ?? [] }));
        const r = await bakeAndScore(input, recipe);
        verified.push({ why: String(sug.why || "").slice(0, 300), recipe, verified: r });
    }
    verified.sort((a, b) => (b.verified.ok ? b.verified.score : -1) - (a.verified.ok ? a.verified.score : -1));
    return { ok: true, provider: c.name, model: cfg.model, suggestions: verified };
}

function parseJson(text) {
    try { return JSON.parse(text); } catch { /* fall through */ }
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    try { return JSON.parse(m[0]); } catch { return null; }
}
