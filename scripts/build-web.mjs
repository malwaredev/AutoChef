/**
 * Builds the browser-only edition into web/ (static files: host on GitHub Pages or any web server).
 *   node scripts/build-web.mjs
 */
import * as esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const OUT = path.join(ROOT, "web");
const shim = p => path.join(ROOT, "src", "browser", "shims", p);
const alias = {
    crypto: shim("crypto.mjs"), zlib: shim("zlib.mjs"), path: require.resolve("path-browserify"),
    stream: require.resolve("stream-browserify"), buffer: require.resolve("buffer/"), util: require.resolve("util/"), events: require.resolve("events/"),
    fs: shim("fs.mjs"), url: shim("url.mjs"), module: shim("module.mjs"), os: shim("empty.mjs"), child_process: shim("empty.mjs"), worker_threads: shim("empty.mjs"),
    vm: shim("empty.mjs"), http: shim("empty.mjs"), https: shim("empty.mjs"), net: shim("empty.mjs"), tls: shim("empty.mjs"), readline: shim("empty.mjs"),
};
const nodePlugin = {
    name: "node-builtins",
    setup(b) {
        // CyberChef's vendored GOST code assigns to an import (allowed by webpack, not by ES modules)
        b.onLoad({ filter: /vendor[\\/]gost[\\/]gost(Digest|Cipher)\.mjs$/ }, a => ({ contents: fs.readFileSync(a.path, "utf8").replace(/^\s*GostRandom = GostRandom \|\| root\.GostRandom;/m, ""), loader: "js" }));
        // the lzma package loads its worker with a computed require(); use its ES-module build
        b.onResolve({ filter: /^@blu3r4y\/lzma$/ }, () => ({ path: path.join(ROOT, "node_modules", "@blu3r4y", "lzma", "src", "lzma_worker-min.mjs") }));
        // browser versions of the Node-only modules (same exports)
        const SWAP = { "./pool.mjs": "pool.mjs", "./plugins.mjs": "plugins.mjs", "./intel.mjs": "intel.mjs" };
        b.onResolve({ filter: /^\.\/(pool|plugins|intel)\.mjs$/ }, a => a.importer.includes(`${path.sep}src${path.sep}browser${path.sep}`) || !a.importer.startsWith(path.join(ROOT, "src")) ? undefined : ({ path: path.join(ROOT, "src", "browser", SWAP[a.path]) }));
        b.onResolve({ filter: /^\.\.\/(plugins|intel)\.mjs$/ }, a => a.importer.includes(`${path.sep}src${path.sep}browser${path.sep}`) ? ({ path: path.join(ROOT, "src", "browser", a.path.slice(3)) }) : undefined);
        b.onResolve({ filter: /^cyberchef$/ }, () => ({ path: path.join(ROOT, "src", "browser", "cyberchef-meta.mjs") }));
        b.onResolve({ filter: /^cyberchef\/src\// }, a => ({ path: path.join(ROOT, "node_modules", a.path) }));
        b.onResolve({ filter: /^(node:)?(crypto|zlib|path|stream|buffer|util|events|fs|url|module|os|child_process|worker_threads|vm|http|https|net|tls|readline)$/ }, a => ({ path: alias[a.path.replace(/^node:/, "")] }));
    },
};
const common = {
    bundle: true, format: "esm", platform: "browser", target: ["chrome110", "firefox115", "safari16"], minify: true, sourcemap: false, logLevel: "warning",
    plugins: [nodePlugin], define: { global: "globalThis", "process.env.NODE_ENV": '"production"' }, inject: [shim("globals.mjs")],
    banner: { js: 'var __dirname="/",__filename="/autochef.js";' },
    loader: { ".json": "json", ".txt": "text", ".png": "dataurl", ".fnt": "text", ".wasm": "file" }, legalComments: "linked",
};
fs.mkdirSync(OUT, { recursive: true });
const t0 = Date.now();
await esbuild.build({ ...common, entryPoints: { "cc-worker": path.join(ROOT, "src", "browser", "cc-worker.mjs") }, outdir: OUT, format: "iife" });
await esbuild.build({ ...common, entryPoints: { autochef: path.join(ROOT, "src", "browser", "entry.mjs") }, outdir: OUT });
console.log(`built web/ in ${((Date.now() - t0) / 1000).toFixed(1)} s`);

// ---- page, offline support and licences
let html = fs.readFileSync(path.join(ROOT, "public", "index.html"), "utf8");
const i = html.lastIndexOf("<script>");
html = html.slice(0, i) + '<script>window.AUTOCHEF_EDITION = "browser";</script>\n<script type="module" src="./autochef.js"></script>\n<script type="module">' + html.slice(i + "<script>".length);
html = html.replace("</head>", '<link rel="manifest" href="manifest.webmanifest">\n<meta name="theme-color" content="#0f1216">\n<script>if ("serviceWorker" in navigator) addEventListener("load", () => navigator.serviceWorker.register("./sw.js").catch(() => {}));</script>\n</head>');
fs.writeFileSync(path.join(OUT, "index.html"), html);
for (const f of ["icon16.png", "icon48.png", "icon128.png"]) fs.copyFileSync(path.join(ROOT, "extension", f), path.join(OUT, f));
fs.writeFileSync(path.join(OUT, "manifest.webmanifest"), JSON.stringify({ name: "AutoChef", short_name: "AutoChef", start_url: "./", display: "standalone", background_color: "#0f1216", theme_color: "#0f1216", icons: [{ src: "icon128.png", sizes: "128x128", type: "image/png" }, { src: "icon48.png", sizes: "48x48", type: "image/png" }] }, null, 1));
const files = fs.readdirSync(OUT).filter(f => !/^(sw\.js|wtest\.html)$/.test(f) && !f.endsWith(".LEGAL.txt"));
const version = (await import("node:crypto")).createHash("sha256").update(files.map(f => f + fs.statSync(path.join(OUT, f)).size).join()).digest("hex").slice(0, 12);
fs.writeFileSync(path.join(OUT, "sw.js"), `// offline cache for the browser edition (version ${version})
const CACHE = "autochef-${version}", FILES = ${JSON.stringify(["./", ...files.filter(f => f !== "index.html").map(f => "./" + f)])};
self.addEventListener("install", e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting())));
self.addEventListener("activate", e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener("fetch", e => { if (e.request.method !== "GET" || new URL(e.request.url).origin !== location.origin) return; e.respondWith(caches.match(e.request, { ignoreSearch: true }).then(r => r || fetch(e.request))); });
`);
for (const f of ["LICENSE", "NOTICE"]) fs.copyFileSync(path.join(ROOT, f), path.join(OUT, f + ".txt"));
fs.rmSync(path.join(OUT, "wtest.html"), { force: true });
console.log(`web/: ${fs.readdirSync(OUT).length} files, cache version ${version}`);
