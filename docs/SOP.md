# Standard Operating Procedure: decoding suspicious content with AutoChef

| | |
|---|---|
| **Document** | SOP-AUTOCHEF-001 |
| **Applies to** | SOC analysts, incident responders, threat-intel and malware analysts |
| **Tool** | AutoChef (this repository), built on GCHQ CyberChef |
| **Owner** | The security team that operates AutoChef (fill in) |
| **Last updated** | 23 November 2026 (v1.2) |
| **Review** | Every 6 months, or when AutoChef adds or changes a feature |

---

## 1. Purpose

This procedure describes how to use AutoChef to decode, decrypt and triage suspicious content safely and consistently. It also covers how to record the results and how to hand them on to detection and threat-intel teams. Content in scope includes obfuscated scripts, encoded command lines, malicious documents, ransom notes, configuration blobs and binaries.

## 2. Scope

**In scope:**

- Static decoding of text and files.
- Macro extraction from Office documents.
- Static analysis of Windows executables.
- Identification of ransom notes.
- Extraction of indicators and creation of alerts.
- Export of results to case notes, MISP, STIX, Sigma and YARA.

**Out of scope:**

- Running or detonating samples. Use the sandbox procedure for that.
- Memory forensics.
- Recovering files that ransomware has encrypted. AutoChef cannot do this without the key, and neither can any other tool (see §9).

## 2a. Editions: browser vs. local

AutoChef comes in two editions built from the same engine. Both keep samples on the analyst's own
computer; they differ in where the code runs and in the features that need other systems.

| | **Browser edition** (online site, like CyberChef) | **Local version** (`npm start`, `start.bat` or Docker) |
|---|---|---|
| How it runs | Static web page; analysis runs in the browser tab (Web Workers) | Node.js server on `127.0.0.1` (or the team's container) |
| Where samples go | Stay in the browser tab: never uploaded | Stay on the machine running AutoChef |
| Install | None: open the team's AutoChef URL (works offline after the first visit) | Node.js 22 + `npm run setup`, or Docker |
| Decoding, editor, keys, findings, alerts, crypto checksums, Office, PE, ransom notes, readable view, exports, batch | Same | Same |
| Reputation lookups | Bitcoin on Blockstream; VirusTotal, AbuseIPDB, URLhaus and MalwareBazaar open **as links on their own sites** | VirusTotal, AbuseIPDB, URLhaus with the team's keys, plus Blockstream |
| Team library | Stored **in that browser only**; shared by Export / Import | JSON file on disk, shared via folder or git |
| Plugins | Bundled plugins; extra plugin files only for the current session, after a warning | Every plugin in the `plugins/` folder |
| AI assistant | Called directly from the page; only providers that allow browser calls (e.g. Anthropic, OpenRouter, OpenAI, local Ollama/LM Studio with browser access enabled) | Called from the local server; every provider |
| DES / 3DES pre-checks | Available | Only if Node's OpenSSL provides DES |
| Blowfish / RC2 pre-checks | Not available (the editor can still run them) | Only if Node's OpenSSL provides them |
| Command line, `--batch` reports to disk, browser extension | No | Yes |
| Performance | Same analysis speed and results on the same computer (deep test 92.4 % vs 92.6 %, within a few cases); first load ~27 MB, cached afterwards; a few seconds of start-up after opening the page, during which Magic's extra suggestions are skipped; very large files limited by browser memory | The analyst's computer (or the server's), files up to 20 MB in the web UI |

**Which edition to use**

1. **Quick triage, phishing analysis, any workstation without Node.js:** the browser edition,
   from the team's own hosted copy (§2b).
2. **Incident response with many files, reputation lookups with API keys, command-line or
   scripted work, the CyberChef browser extension:** the local version.
3. **TLP:RED or legally restricted material:** either edition keeps the data local, but use the
   local version or a browser edition the team hosts itself, **never a copy on a site the team does
   not control** (the code of a web page comes from its host every time it is loaded).
4. Results are the same in both editions; if they ever differ for a sample, record it and report
   it to the tool owner.

## 2b. Hosting the browser edition (tool owner)

1. Build it with `npm run build:web` (output in `web/`) or let the Pages workflow
   (`docs/pages-workflow.yml`) build, test and publish it.
2. Host it on a site the team controls (GitHub Pages of the team's repository, or an internal
   web server). Serve it over HTTPS.
3. Before publishing a new version, run `npm run test:browser` (§12) and compare with the
   previous figures.
4. Tell analysts the official URL. Do not use copies hosted by others.

## 3. Roles

| Role | Responsibility |
|---|---|
| Analyst | Runs AutoChef, validates results, records findings, raises alerts |
| Senior analyst / reviewer | Approves exported detections (Sigma/YARA), approves team-library entries, approves any external lookup for sensitive cases |
| Tool owner | Keeps AutoChef updated: `npm run setup` after updates, the ransom signature rebuild (§11), and the test runs (§12) |

## 4. Safety rules (always)

1. **Work in the analysis environment.** That means an isolated analysis VM (local version, or the browser edition opened in the VM's browser), or the Docker container published on `127.0.0.1` only. Never open samples on a production workstation.
2. **Never execute decoded output.** AutoChef never runs anything. If you download a decoded file, keep the `.exe_` / `.pdf_` style extension that AutoChef gives it.
3. **Handle samples in password-protected zips** (password `infected`). AutoChef's batch mode opens these directly, so there is no need to extract them to disk.
4. **Treat everything as confidential unless the case owner says otherwise.** The AI assistant and the reputation lookups are the only features that send data outside the machine:
   - **AI assistant:** use only a local model (Ollama / LM Studio), or a cloud provider approved for the case's TLP level.
   - **Look up:** sends one indicator to the chosen service. Do not look up indicators from TLP:RED cases, or indicators that reveal the victim (internal host names, user names, internal IPs).
5. **Defang indicators** in tickets, chat and e-mail. The Markdown and CSV reports do this automatically (`hxxp`, `[.]`).
6. **Do not commit samples** to the AutoChef repository or the team library. Only recipes, notes and detection patterns go there.

## 5. Preparation (once per analyst workstation)

1. **Browser edition:** open the team's official AutoChef URL (§2b). Nothing to install.
   **Local version:** install Node.js 22+ and run `npm run setup` in the AutoChef folder, or build the Docker image (see README).
2. Local version: start AutoChef with `npm start` or `start.bat`, then open http://127.0.0.1:8471.
3. Optional, under **Settings** (the browser edition has no threat-intel key fields, see §2a):
   - Enter the AI provider and model approved for your team.
   - Enter threat-intel API keys (VirusTotal, AbuseIPDB, abuse.ch).

   All keys are held in memory only and must be entered again after a restart.
4. Confirm that the team library is the shared one: **Recipe library → Team library** shows the file path. Set `AUTOCHEF_LIBRARY` to the team's shared file if needed.

## 6. Procedure: single sample

### 6.1 Intake

1. Record in the case:
   - the source (e-mail, EDR alert, file share);
   - the time collected;
   - the SHA-256 (shown in every AutoChef report).
2. **Text** (command line, script fragment, Base64 blob): paste it into **Input**.
3. **File** (document, script, binary, ransom note): drop it on the drop zone. Keep the original file name; it is used to recognise ransom-note file names.
4. **Encryption keys:** if you have a key, password or IV (from a loader script, a memory dump or a config), type it into **Keys / passwords / IVs**, one per line.
5. **Crib:** if you know text that should appear in the output (`http`, `MZ`, a domain), put it in **Crib**.

### 6.2 Run

1. Click **Find recipe**. Default limits are 12 s and 64 steps.
2. If nothing convincing is found, raise **Time limit** to 30–60 s and run again.
3. *Browser edition:* right after opening the page, wait a few seconds before the first run, or
   simply run again if the first result looks thin; CyberChef is still starting in the background
   and Magic's extra suggestions are skipped until it is ready.

### 6.3 Read the verdict banners first

The banners appear above the results. Act on them before reading the recipes.

| Banner | Meaning | Action |
|---|---|---|
| 🏴 **Ransom note: family** | The note matches that family on exact evidence (onion site, e-mail, Tox ID, unique line). | Follow §9. If a No More Ransom decryptor link is shown, give it to the recovery lead. |
| 🔒 **Encrypted data, no key** | High-entropy data with no key in the sample. | Do not keep trying random recipes. Look for the key (loader script, memory, config) and use the Keys field. For ransomware files, see §9. |
| # **One-way hash** | The input is a hash, not an encoding. | Record it as a hash indicator. Look it up (§6.6) if allowed. |
| 📄 **Office document** | Macros, macro sheets, links and stream strings were extracted. Result #1 is the extracted source. | Review the macro source; the recipes below it decode the payload. |
| 🧩 **Windows executable** | Static PE details. | Record the imphash, compile time, notable imports and warnings in the case. |
| ⚠ **Findings** | Indicators with alert levels. | Follow §6.5. |
| **Already readable *script* text** (no results) | The input is natural text in a non-Latin script (Thai, Japanese, Chinese, Korean, Cyrillic, Arabic, …) and nothing hidden was found. | Translate it if needed. If you still suspect hidden content, add a crib (§6.2) or build the recipe in the editor. |

**Text that looks like Chinese, Japanese or Korean but makes no sense** (for example `乄久乔久乃乔…`) is often a byte encoding: every character is one byte plus a fixed offset (U+4E00 in the five-layer loader Fortra documented). AutoChef decodes it with `To Charcode → Find / Replace → From Hex` (plus `SUB` for offsets that are not a multiple of 256) and names the offset in the explanation. The decoded bytes can be a further layer (Base64, compressed data) or a .NET/PE file.

### 6.4 Validate the recipe

1. Read result #1:
   - the confidence (high / medium / low);
   - the step-by-step explanation;
   - the output preview.
2. **Accept** a result only if the output is meaningful (readable code, a real file type, sensible indicators). Low confidence means the result is a lead to verify, not a conclusion.
3. Click **Edit recipe** to verify or adjust it:
   - Changes bake immediately. Use **▶ Run recipe** when auto-bake is off, and **Undo/Redo** to step back.
   - Turn on **Step outputs** to see the result after every step and find where a recipe breaks.
   - A failing step is outlined in red with CyberChef's error message.
4. Click **Open in CyberChef** to reproduce the result in the official CyberChef. Do this for every result you report.
5. For scripts, open **Readable view** to get a cleaned-up copy. Quote the decoded output itself as evidence; the readable view is only an aid for understanding the script.
6. If the result is a new or larger payload, click **Use output as input** to continue with the next stage.

### 6.5 Triage the findings (alerts)

| Level | Includes | Required action |
|---|---|---|
| **High** | URLs, IPs, domains, cryptocurrency addresses, exfiltration channels (Telegram bot tokens, Discord/Slack webhooks) | Add to the case IOC list. Check them against blocklists and proxy/DNS logs. Raise a detection or block request through the normal change process. |
| **Medium** | E-mail addresses, hashes, registry paths, Windows paths, process names, user names, paste and tunnel services | Use for hunting (EDR queries for the paths, processes and registry keys). User names may identify a victim or an attacker account: handle them as personal data. |
| **Info** | File names, phone numbers, country names, certificate/schema hosts | Context only. Phone numbers and country names in ransom notes or phishing go into the case notes. |

**Notes on the checks:**

- **Cryptocurrency addresses** marked *checksum verified* are real address formats. Ones marked *format match* only look like addresses: verify them on the explorer link before reporting.
- **Certificate and schema hosts** (for example `crl.sectigo.com` and `schemas.microsoft.com`) are labelled *info* because they appear in almost every signed binary. Do not report them as indicators.

### 6.6 Enrichment (optional, follow §4.4)

1. Click **Look up** next to a finding. Only that single value is sent to the services you configured.
   In the **browser edition**, Look up checks Bitcoin addresses on Blockstream and otherwise opens
   VirusTotal / AbuseIPDB / URLhaus / MalwareBazaar **in a new tab with the value in the address**:
   opening such a link shares the value with that site, so the same rule (§4.4) applies.
2. Record each verdict with its service name and date, for example: "VirusTotal 2026-11-22: 12/94 malicious".
3. Treat provider verdicts as opinions: an "unknown" result does not mean the indicator is benign.

### 6.7 AI assistant (optional, follow §4.4)

1. Click **Ask AI for more recipes** when AutoChef's own results are weak.
2. Every AI proposal is run and scored by CyberChef. Treat a proposal like any other recipe and validate it through §6.4.

## 7. Procedure: batch / incident triage

1. Click **Batch** in the web app. On the command line, use:

   ```
   node bin/autochef.mjs --batch <folder or zip> --report md --out batch.md
   ```
2. Use the zip password `infected` unless the case uses another one, and allow 8–15 s per file.
3. Review the table and start with files that have high-level alerts, a ransom family or an encrypted verdict.
4. Re-open any important file on its own (§6) to validate its recipe.
5. Attach the batch report (`.md`) to the case. Export **MISP** or **STIX** for the threat-intel team (§8).

## 8. Recording and handover

| Output | Use | How |
|---|---|---|
| Markdown report | Case notes, ticket | **Export .md** (single sample) or the batch report |
| CSV of findings | IOC lists, spreadsheets | **IOCs .csv** |
| JSON | Archive, automation | **.json** |
| MISP event | Threat-intel platform | **Export to… → MISP event**. Distribution is "your organisation", the event is not published and is tagged `tlp:amber`. The intel team decides on publishing. |
| STIX 2.1 bundle | Sharing with partners and TIPs | **Export to… → STIX 2.1 bundle** |
| Sigma rule | Detection engineering | **Export to… → Sigma rule**. It is a starter: a senior analyst must review the fields, tune it for the log source and test it for false positives before deployment. |
| YARA rule | Hunting in files and memory | **Export to… → YARA rule**. It is a starter, and it matches the *decoded* content. Test it on known-good files before deployment. |

**Every case record must contain:**

- the sample SHA-256;
- the final CyberChef recipe;
- the confidence;
- the validated findings;
- any keys used, and where they came from;
- the exports you produced.

## 9. Ransomware cases

1. **Identify the family.** Paste or drop the ransom note. AutoChef names the family only on exact evidence and shows a No More Ransom decryptor link when one is listed.
2. **Check decryptors.** A listed decryptor may only work for some versions of a family. Test it on a *copy* of an encrypted file first.
3. **If no family is identified,** upload the note and one encrypted file to No More Ransom's Crypto Sheriff (link shown by AutoChef). Do this only if the case owner approves sharing them.
4. **Encrypted files** will show the "Encrypted data, no key" verdict. This is expected. Do not spend time trying recipes on them. Recovery needs the attacker's key, a published decryptor, or backups.
5. **Record the indicators:** the onion sites, e-mail addresses, Tox IDs and wallet addresses from the note are high-value indicators.

## 10. Team library (sharing recipes)

0. **Browser edition:** the library lives in your browser only. Export it after saving entries
   and add it to the team's shared copy (git or folder); import the shared copy when you start
   on a new browser or computer. Clearing the browser's site data deletes the local copy.
1. **When to save:** after you have validated a recipe for a recurring technique (§6.4), click **Save to library** on the result or in the editor.
2. **What to fill in:**
   - **Name:** the technique and what it does, for example "Emotet doc: filler token + Base64 + UTF-16".
   - **Family / campaign.**
   - **Notes:** where it was seen, and the case number.
   - **Detection patterns:** one or more regular expressions that must all match the input, so the recipe is tried only on similar samples.
3. **Never** put sample content, secrets or victim data in the notes.
4. **Review:** a senior analyst reviews new entries weekly. Export the library (**Recipe library → Team library → Export**) for review and backup, or keep `data/team-library.json` in the team's git repository.
5. **Retire** entries that no longer match current campaigns.

## 11. Maintenance (tool owner)

| Task | Frequency | How |
|---|---|---|
| Update AutoChef | Monthly or on release | `git pull`, then `npm run setup` |
| Rebuild and re-test the browser edition, republish | After every update | `npm run build:web`, `npm run test:browser`, then the Pages workflow (§2b) |
| Rebuild ransom-note signatures and decryptor list | Monthly | See the header of `scripts/build-ransom-signatures.mjs` (`npm run build:ransom`) |
| Run the test suites | After every update | §12 |
| Review plugins in `plugins/` | On every change | Plugins run with full rights; review the code before adding one |
| Rotate threat-intel / AI keys | Per key policy | Keys are in memory only; nothing to clean up on disk |

## 12. Verification of the tool

Run these after installation and after every update. All suites must pass before analysts use the new version.

```
npm test                   # basic encodings (18/18)
npm run test:typical       # 35 typical test strings
npm run test:features      # crypto checksums, Office, PE, exports, cleanup, library, plugins, ransom notes, Unicode/ADD layers (44/44)
npm run test:library       # recipe library on real samples (11/11)
npm run test:ui            # web app in a real browser
npm run test:advanced      # 1,520 deep cases (about 1 hour)
npm run build:web && npm run test:browser   # the browser edition: same suites inside Chromium
                                            # (35/35, 18/18, ~92.4 % / 93.9 % deep test, 13/13 UI)
```

Compare the results with the figures in the README "Test results" section. If a suite fails or a figure drops noticeably, do not roll out the update.

## 13. References

- GCHQ CyberChef: https://github.com/gchq/CyberChef
- No More Ransom: https://www.nomoreransom.org
- ThreatLabz ransom notes: https://github.com/ThreatLabz/ransomware_notes
- STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- MISP: https://www.misp-project.org
- Sigma: https://sigmahq.io
- YARA: https://virustotal.github.io/yara/
- FIRST Traffic Light Protocol 2.0: https://www.first.org/tlp/

## 14. Revision history

| Version | Date | Change |
|---|---|---|
| 1.2 | 2026-11-23 | §6.3: "already readable" verdict for natural non-Latin text, and how CJK-looking byte encodings (Unicode code-point offset) are decoded. Owner field made generic. |
| 1.1 | 2026-11-22 | Browser edition added: §2a (differences and which edition to use), §2b (hosting), browser notes in §4, §5, §6.2, §6.6, §10, §11, §12, measured results of both editions. |
| 1.0 | 2026-11-22 | First version. Covers the editor history and step view, readable view, PE analysis, Office macro extraction, ransom-note identification, findings and alerts, reputation lookups, STIX/MISP/Sigma/YARA exports, team library, batch mode, plugins, Docker and CI. |
