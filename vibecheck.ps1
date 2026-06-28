<#
.SYNOPSIS
  vibecheck — AI-code pre-launch health check (claw venture #1 MVP).
  Scans a repo for the security/reliability smells AI codegen tools (Cursor,
  Claude, Lovable, Bolt, v0, Replit) most commonly leave, and emits a
  severity-ranked report as Markdown or a self-contained HTML dashboard.
.DESCRIPTION
  READ-ONLY. Never modifies the target. Heuristic triage, NOT a penetration
  test — finds known smells, not a clean bill of health. Output is English for
  portability (PS 5.1 non-BOM CJK safety); write the client-facing report from it.
.PARAMETER Path    Target repo root.
.PARAMETER OutFile Write report to this file (extension implies format if -Format omitted).
.PARAMETER Format  md | html (default md).
.EXAMPLE
  pwsh vibecheck.ps1 -Path C:\repo -OutFile report.html -Format html
#>
param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string]$OutFile,
  [ValidateSet('md','html')][string]$Format = 'md'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Path)) { Write-Error "Path not found: $Path"; exit 1 }
if (-not $Format -and $OutFile -and $OutFile -match '\.html?$') { $Format = 'html' }

$exts = '*.js','*.ts','*.jsx','*.tsx','*.mjs','*.cjs','*.py','*.cs','*.go','*.rb','*.php','*.java','*.env','*.yml','*.yaml','*.json','*.tf'
$exclude = 'node_modules','.git','vendor','dist','build','.next','out','bin','obj','.venv','__pycache__','packages'

# Severity, Name, Regex, Why
$rules = @(
  @{ Sev='BLOCKER'; Name='Hardcoded secret/password'; Rx='(?i)(api[_-]?key|secret|passwd|password|access[_-]?token|bearer)\s*[:=]\s*["''][^"'']{8,}'; Why='Credential hardcoded in source; a leak = account takeover.' }
  @{ Sev='BLOCKER'; Name='AWS access key'; Rx='AKIA[0-9A-Z]{16}'; Why='AWS access key exposed in code.' }
  @{ Sev='BLOCKER'; Name='Private key material'; Rx='-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'; Why='Private key committed to the repo.' }
  @{ Sev='BLOCKER'; Name='Server secret in client bundle'; Rx='(?i)(service_role|sk_live_[0-9a-z]+|SUPABASE_SERVICE_ROLE)'; Why='Server-only key (service_role / sk_live) shipped to the browser — the modal vibe-coded leak.' }
  @{ Sev='HIGH'; Name='CORS wildcard'; Rx='(?i)(access-control-allow-origin["'']?\s*[:,]\s*["'']\*|origin\s*:\s*["'']\*)'; Why='Any origin allowed; CSRF / data exfiltration risk.' }
  @{ Sev='HIGH'; Name='SQL string concatenation'; Rx='(?i)(select|insert|update|delete)\s+[^;]{0,80}(\+|\$\{|%s|f["''])'; Why='Query built by string interpolation — SQL injection.' }
  @{ Sev='HIGH'; Name='Dynamic eval/exec'; Rx='(?i)\b(eval|exec)\s*\('; Why='Arbitrary code execution if user input reaches it.' }
  @{ Sev='HIGH'; Name='Command injection'; Rx='(?i)(child_process|os\.system|subprocess|Runtime\.getRuntime)[^\n]{0,60}(\+|\$\{|f["''])'; Why='Shell command built from interpolation — command injection.' }
  @{ Sev='HIGH'; Name='Unsafe deserialization'; Rx='(?i)(pickle\.loads|yaml\.load\s*\((?![^)]*Safe)|Marshal\.load)'; Why='Untrusted input deserialization can run code.' }
  @{ Sev='HIGH'; Name='XSS sink'; Rx='(?i)(dangerouslySetInnerHTML|\.innerHTML\s*=)'; Why='Raw HTML injection — XSS if data is user-controlled.' }
  @{ Sev='HIGH'; Name='TLS verification disabled'; Rx='(?i)(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)'; Why='Man-in-the-middle risk.' }
  @{ Sev='HIGH'; Name='JWT alg none / hardcoded secret'; Rx='(?i)(algorithm["'']?\s*[:=]\s*["'']none["'']|jwt[_-]?secret\s*[:=]\s*["''][^"'']+)'; Why='Forgeable tokens.' }
  @{ Sev='MEDIUM'; Name='Debug mode enabled'; Rx='(?i)(debug\s*=\s*true|app\.debug\s*=\s*true|DEBUG\s*:\s*true)'; Why='Verbose error pages leak internals.' }
  @{ Sev='MEDIUM'; Name='Non-TLS endpoint'; Rx='(?i)["''](http://(?!localhost|127\.0\.0\.1))[^"''\s]+["'']'; Why='Plaintext HTTP endpoint.' }
  @{ Sev='MEDIUM'; Name='Security-related TODO'; Rx='(?i)(TODO|FIXME|HACK)[^\n]{0,60}(auth|secur|secret|password|token|temp)'; Why='Unfinished security-relevant work.' }
)

function HtmlEnc([string]$s) { if ($null -eq $s) { return '' } $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' }

$findings = New-Object System.Collections.Generic.List[object]
$files = Get-ChildItem -Path $Path -Recurse -File -Include $exts -ErrorAction SilentlyContinue |
  Where-Object { $fp = $_.FullName; -not ($exclude | Where-Object { $fp -match "[\\/]$([Regex]::Escape($_))[\\/]" }) }
$scanned = 0
foreach ($f in $files) {
  $scanned++
  foreach ($r in $rules) {
    foreach ($h in (Select-String -Path $f.FullName -Pattern $r.Rx -AllMatches -ErrorAction SilentlyContinue)) {
      $findings.Add([pscustomobject]@{
        Sev=$r.Sev; Rule=$r.Name; Why=$r.Why
        File=$f.FullName.Substring($Path.Length).TrimStart('\','/')
        Line=$h.LineNumber; Text=($h.Line.Trim() -replace '\s+',' ')
      })
    }
  }
}
# .env present but not gitignored
$envFile = Join-Path $Path '.env'; $giFile = Join-Path $Path '.gitignore'
if ((Test-Path $envFile) -and -not ((Test-Path $giFile) -and (Select-String -Path $giFile -Pattern '^\s*\.env' -Quiet))) {
  $findings.Add([pscustomobject]@{ Sev='BLOCKER'; Rule='.env not gitignored'; Why='Secrets may be committed.'; File='.env'; Line=0; Text='.env exists but .gitignore does not exclude it' })
}

$sevOrder = 'BLOCKER','HIGH','MEDIUM','LOW'
$counts = @{}; foreach ($s in $sevOrder) { $counts[$s] = @($findings | Where-Object { $_.Sev -eq $s }).Count }
$verdict = if ($counts['BLOCKER'] -gt 0) { 'DO NOT SHIP — blockers present' } elseif ($counts['HIGH'] -gt 0) { 'Risky — fix HIGH before shipping' } elseif ($findings.Count -gt 0) { 'Mostly OK — review findings' } else { 'No known smells matched (still needs human review)' }

if ($Format -eq 'html') {
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append("<!doctype html><html><head><meta charset='utf-8'><title>vibecheck report</title><style>")
  [void]$sb.Append("body{font:14px/1.5 -apple-system,Segoe UI,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}")
  [void]$sb.Append(".wrap{max-width:900px;margin:0 auto;padding:32px}h1{font-size:22px}")
  [void]$sb.Append(".verdict{padding:12px 16px;border-radius:8px;background:#1b1f29;margin:16px 0;font-weight:600}")
  [void]$sb.Append(".badges span{display:inline-block;padding:4px 10px;border-radius:6px;margin-right:8px;font-weight:600}")
  [void]$sb.Append(".BLOCKER{background:#5a1620;color:#ff9aa6}.HIGH{background:#5a3a16;color:#ffc879}.MEDIUM{background:#3a4a16;color:#cfe88a}.LOW{background:#16304a;color:#9ac8ff}")
  [void]$sb.Append(".card{background:#1b1f29;border-left:4px solid #444;border-radius:6px;padding:10px 14px;margin:8px 0}")
  [void]$sb.Append(".card.BLOCKER{border-color:#ff5566}.card.HIGH{border-color:#ffaa44}.card.MEDIUM{border-color:#aacc44}")
  [void]$sb.Append(".loc{color:#7aa2f7;font-family:monospace}.why{color:#aaa;font-size:13px}.code{font-family:monospace;background:#0a0c10;padding:6px 8px;border-radius:4px;display:block;margin-top:6px;overflow-x:auto;color:#d7dae0}")
  [void]$sb.Append("h2{margin-top:28px}.muted{color:#888;font-size:12px}</style></head><body><div class='wrap'>")
  [void]$sb.Append("<h1>vibecheck — AI-code pre-launch report</h1>")
  [void]$sb.Append("<p class='muted'>Target: " + (HtmlEnc $Path) + " &middot; files scanned: $scanned &middot; heuristic triage, not a pen-test</p>")
  [void]$sb.Append("<div class='verdict'>" + (HtmlEnc $verdict) + "</div>")
  [void]$sb.Append("<div class='badges'>")
  foreach ($s in $sevOrder) { [void]$sb.Append("<span class='$s'>$s $($counts[$s])</span>") }
  [void]$sb.Append("</div>")
  foreach ($s in $sevOrder) {
    $g = @($findings | Where-Object { $_.Sev -eq $s })
    if ($g.Count -eq 0) { continue }
    [void]$sb.Append("<h2>$s ($($g.Count))</h2>")
    foreach ($x in $g) {
      [void]$sb.Append("<div class='card $s'><b>" + (HtmlEnc $x.Rule) + "</b> <span class='loc'>" + (HtmlEnc "$($x.File):$($x.Line)") + "</span>")
      [void]$sb.Append("<div class='why'>" + (HtmlEnc $x.Why) + "</div>")
      [void]$sb.Append("<code class='code'>" + (HtmlEnc $x.Text) + "</code></div>")
    }
  }
  [void]$sb.Append("</div></body></html>")
  $out = $sb.ToString()
} else {
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('# vibecheck — AI-code pre-launch report'); [void]$sb.AppendLine('')
  [void]$sb.AppendLine("> Target: $Path  |  files scanned: $scanned"); [void]$sb.AppendLine('> Heuristic triage — not exhaustive, not a penetration test.'); [void]$sb.AppendLine('')
  [void]$sb.AppendLine("**Verdict: $verdict**"); [void]$sb.AppendLine('')
  [void]$sb.AppendLine('## Summary'); foreach ($s in $sevOrder) { [void]$sb.AppendLine("- $s`: $($counts[$s])") }; [void]$sb.AppendLine('')
  foreach ($s in $sevOrder) {
    $g = @($findings | Where-Object { $_.Sev -eq $s }); if ($g.Count -eq 0) { continue }
    [void]$sb.AppendLine("## $s ($($g.Count))")
    foreach ($x in $g) { [void]$sb.AppendLine("- **$($x.Rule)** -- ``$($x.File):$($x.Line)``"); [void]$sb.AppendLine("  - $($x.Why)"); [void]$sb.AppendLine("  - ``$($x.Text)``") }
    [void]$sb.AppendLine('')
  }
  $out = $sb.ToString()
}

if ($OutFile) { $out | Out-File -FilePath $OutFile -Encoding utf8; Write-Host "vibecheck: $($findings.Count) findings ($($counts['BLOCKER']) BLOCKER, $($counts['HIGH']) HIGH). Report -> $OutFile" }
else { Write-Output $out }
