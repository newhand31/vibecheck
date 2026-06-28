# vibecheck

**AI-code pre-launch health check.** Point it at a repo built with Cursor / Claude / Lovable / Bolt / v0 / Replit, get a severity-ranked report of the security & reliability landmines AI codegen most often leaves — before you ship.

Read-only. Zero backend. Heuristic triage (finds known smells — *not* a penetration test, *not* a clean bill of health).

## Quick start

```powershell
# Markdown to console
pwsh vibecheck.ps1 -Path C:\path\to\your\repo

# Self-contained colored HTML report (open in a browser)
pwsh vibecheck.ps1 -Path C:\path\to\your\repo -OutFile report.html -Format html
```

> Use **PowerShell 7+ (`pwsh`)**. Output is English for portability.

## What it catches

Multi-language (JS/TS/JSX/TSX/Python/C#/Go/Ruby/PHP/Java + config). Rules include:

- **Server secret shipped to the client** (`service_role` / `sk_live_…`) — the #1 vibe-coded leak
- Hardcoded secrets / passwords, AWS keys, private keys, `.env` not gitignored
- CORS wildcard, SQL string concatenation, `eval`/`exec`, command injection
- Unsafe deserialization, XSS sinks (`dangerouslySetInnerHTML` / `innerHTML =`)
- Disabled TLS verification, JWT `alg: none` / hardcoded JWT secret
- Debug mode on, plaintext HTTP endpoints, security-related TODOs

It **won't** catch things that need semantic understanding (broken object-level auth / IDOR, missing auth on routes, race conditions, N+1, hallucinated APIs, missing error handling). Those need a human pass.

## Sample output

Run against the bundled `sample/app.js` (deliberately vulnerable, fake values):

```
Verdict: DO NOT SHIP — blockers present
Summary: BLOCKER: 4 | HIGH: 5 | MEDIUM: 3 | LOW: 0

## BLOCKER (4)
- Server secret in client bundle -- app.js:11
- Hardcoded secret/password    -- app.js:7
...
```

## Why

AI codegen tools repeatedly ship apps with the same authorization and credential failures (leaked `service_role`/`sk_live` keys, BOLA in generated CRUD, stubbed-out auth). `vibecheck` is a fast first pass so you catch the obvious landmines before launch.

## License

MIT — see [LICENSE](LICENSE).

## Support

If this saved you from shipping a leak, support is welcome (see `.github/FUNDING.yml`).
