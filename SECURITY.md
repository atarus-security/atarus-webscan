# Security policy

## Reporting a vulnerability

Please report security issues in atarus-webscan privately by email to info@atarussecurity.com. Do not open a public GitHub issue for a vulnerability.

Include:

- the version or commit you tested
- steps to reproduce, and a proof of concept if you have one
- the impact you expect

We aim to acknowledge reports within 5 business days and to agree a fix and disclosure date with you. We are happy to credit reporters who want credit.

## Supported versions

Only the latest release on the default branch receives security fixes.

## Scope

In scope: the code in this repository and the reports it generates.

Out of scope: third-party tools this project calls or downloads (for example nuclei and its templates), and findings that require an attacker who already controls the machine running the tool.

## Using this tool

atarus-webscan is passive by default: a plain run sends one GET, one HEAD and one OPTIONS to the URL you named and nothing else. Active checks (sensitive-file probing, the state-changing method probes POST, PUT, PATCH, DELETE, TRACE and CONNECT, nuclei) run only with `--active`, against a host inside a `--scope` you provide, after you type `yes` on the terminal (or pass `--yes` together with `--scope` for scripted runs). State-changing methods go only to paths you name with `--probe-path`. Only use `--active` against applications you own or are authorized in writing to test.

Treat as a security bug and report it: any run that sends more than those three safe requests without `--active`, any request to a scheme, host, port or path outside the named origin (including a followed off-origin redirect), any state-changing method sent to a path the user did not name, any sensitive-file read beyond 512 bytes or any report that stores a candidate secret's content, any way to pass the confirmation gate other than typing `yes` on the terminal or the documented `--yes` flag, a run that skips TLS verification without `--insecure`, a report that reads as clean for a check that did not run, and any network destination not listed in the README's network table.
