# Security policy

AutoChef is a defensive analysis tool. It decodes and decrypts content that analysts already
have (phishing attachments, scripts, configuration blobs, logs) so they can understand it.
It does not contain malware, exploits or attack infrastructure, and this repository does not
store malware samples: the real-world tests download published samples at run time into
`test/realworld/.cache/`, which is excluded by `.gitignore`.

## Reporting a vulnerability in AutoChef

Please **do not** open a public issue for a security vulnerability.

Use GitHub's private reporting instead: on this repository, open the **Security** tab and
choose **Report a vulnerability**. Include:

- the AutoChef version (or commit) and edition (local or browser);
- what an attacker could do, and the steps or input that show it;
- whether the input has to be opened by an analyst (most inputs to AutoChef are untrusted).

We aim to acknowledge reports within 7 days and to agree a disclosure date with the reporter.

## Scope

In scope:

- code execution, file access or network requests caused by **analysing** a crafted input,
  in the local server, the command line, the browser edition or the browser extension;
- the local server being reachable from other machines when started with the default settings
  (it listens on `127.0.0.1` only);
- API keys (AI providers, VirusTotal, AbuseIPDB, URLhaus) being exposed, logged or sent anywhere
  other than the provider the user chose;
- cross-site scripting through decoded output, findings, reports or exports.

Out of scope:

- vulnerabilities in CyberChef itself: report them to GCHQ as described in
  [CyberChef's security policy](https://github.com/gchq/CyberChef/security/policy);
- issues that require the attacker to already control the analyst's computer or the site
  hosting the browser edition;
- a plugin file the user chose to load (plugins run with full access by design; see the
  README and SOP).

## Reporting misuse

If you believe content in this repository is being used to support an active attack, open an
issue (or use private reporting if it contains sensitive details) and it will be reviewed
promptly.
