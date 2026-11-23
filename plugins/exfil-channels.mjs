/**
 * AutoChef plugin: exfiltration and C2 channels that info-stealers and RATs write into their
 * scripts and configs – Telegram bot tokens and chat IDs, Discord and Slack webhooks, paste
 * sites, tunnelling services and file-sharing APIs.
 *
 * Token formats: Telegram Bot API (https://core.telegram.org/bots/api#authorizing-your-bot),
 * Discord webhooks (https://discord.com/developers/docs/resources/webhook),
 * Slack incoming webhooks (https://api.slack.com/messaging/webhooks).
 */
const RULES = [
    { type: "Telegram bot token", level: "high", re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, note: "anyone with this token can read the bot's messages" },
    { type: "Telegram API call", level: "high", re: /https?:\/\/api\.telegram\.org\/bot[^\s"'<>]+/gi },
    { type: "Discord webhook", level: "high", re: /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{16,20}\/[\w-]{60,72}/gi },
    { type: "Slack webhook", level: "high", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g },
    { type: "Paste site", level: "medium", re: /https?:\/\/(?:pastebin\.com\/raw\/|paste\.ee\/r\/|rentry\.(?:co|org)\/[\w-]+\/raw|hastebin\.com\/raw\/|ghostbin\.\w+\/paste\/)[\w/-]+/gi },
    { type: "Tunnel service", level: "medium", re: /\b[\w-]+\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|serveo\.net|loca\.lt|portmap\.io|ply\.gg)\b/gi },
    { type: "File-sharing API", level: "medium", re: /https?:\/\/(?:api\.anonfiles\.com|transfer\.sh|file\.io|gofile\.io\/uploadFile|store\d*\.gofile\.io|tmpfiles\.org\/api)[^\s"'<>]*/gi },
];

export default {
    name: "exfil-channels",
    version: "1.0.0",
    description: "Finds Telegram bot tokens, Discord/Slack webhooks, paste sites, tunnels and file-sharing APIs used for exfiltration",
    findings(text) {
        const out = [], seen = new Set();
        for (const r of RULES) for (const m of text.matchAll(r.re)) {
            const v = m[0].replace(/[.,;)'"]+$/, "");
            if (seen.has(v)) continue;
            seen.add(v);
            out.push({ category: "network", type: r.type, value: v, level: r.level, note: r.note });
        }
        return out;
    },
};
