#!/usr/bin/env python3
"""
ai_reporter.py
──────────────
1. Collects all crash logs from all_crashes/ and all_logs/
2. Sends each unique crash to Claude (Anthropic API) for deep analysis
3. Builds a rich Telegram message and sends it
4. Saves full triage JSON reports

Required env vars:
  ANTHROPIC_API_KEY
  TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID
  GITHUB_RUN_URL
  GITHUB_REPO
  FUZZ_ITERATIONS
  HTML_COUNT
"""

import os
import re
import json
import time
import hashlib
import httpx
import anthropic
from pathlib import Path
from datetime import datetime, timezone

# ── Config ──────────────────────────────────────────────
CRASH_DIR   = Path("all_crashes")
LOG_DIR     = Path("all_logs")
TRIAGE_DIR  = Path("triage")
TRIAGE_DIR.mkdir(exist_ok=True)

ANTHROPIC_API_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")
TELEGRAM_BOT_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID    = os.environ.get("TELEGRAM_CHAT_ID", "")
GITHUB_RUN_URL      = os.environ.get("GITHUB_RUN_URL", "")
GITHUB_REPO         = os.environ.get("GITHUB_REPO", "unknown/repo")
FUZZ_ITERATIONS     = os.environ.get("FUZZ_ITERATIONS", "?")
HTML_COUNT          = os.environ.get("HTML_COUNT", "?")

TELEGRAM_API        = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
MAX_CRASH_LOG_CHARS = 6000   # send this many chars to Claude per crash
MAX_TG_MSG_CHARS    = 4000   # Telegram max per message


# ── Crash Signature Patterns ────────────────────────────
CRASH_PATTERNS = {
    "heap-use-after-free":         ("USE-AFTER-FREE",   "🔴"),
    "heap-buffer-overflow":        ("HEAP-OVERFLOW",    "🔴"),
    "stack-buffer-overflow":       ("STACK-OVERFLOW",   "🟠"),
    "use-of-uninitialized-value":  ("UNINIT-VALUE",     "🟡"),
    "double-free":                 ("DOUBLE-FREE",      "🔴"),
    "attempting free on address":  ("INVALID-FREE",     "🟠"),
    "SEGV on unknown address 0x0": ("NULL-DEREF",       "🟠"),
    "SEGV on unknown address":     ("SEGFAULT",         "🟡"),
    "CHECK":                       ("CHECK-FAIL",       "🟡"),
    "DCHECK":                      ("DCHECK-FAIL",      "⚪"),
}

SEVERITY_ORDER = {"🔴": 0, "🟠": 1, "🟡": 2, "⚪": 3}


# ── Helpers ─────────────────────────────────────────────
def detect_crash_type(log_text: str) -> tuple[str, str]:
    for pat, (label, emoji) in CRASH_PATTERNS.items():
        if pat.lower() in log_text.lower():
            return label, emoji
    return "UNKNOWN", "⚪"

def extract_stack_frames(log_text: str, n=15) -> list[str]:
    frames = re.findall(r'#\d+\s+0x[0-9a-f]+ in (\S+.*?)$', log_text, re.M)
    return [f.strip() for f in frames[:n]]

def dedup_hash(crash_type: str, frames: list[str]) -> str:
    sig = crash_type + '|'.join(frames[:5])
    return hashlib.sha256(sig.encode()).hexdigest()[:10]

def truncate(text: str, n: int) -> str:
    if len(text) <= n:
        return text
    return text[:n] + f"\n... [truncated {len(text)-n} chars]"


# ── Claude Analysis ──────────────────────────────────────
def analyze_with_claude(crash_type: str, log_snippet: str, html_snippet: str) -> dict:
    """Send crash to Claude and get structured security analysis."""
    if not ANTHROPIC_API_KEY:
        return {"summary": "No API key — skipping AI analysis", "severity": "unknown",
                "root_cause": "N/A", "next_mutations": [], "cve_similar": "N/A"}

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    prompt = f"""You are a senior Chromium security researcher and memory safety expert.
Analyze this crash from a fuzzer targeting Chromium's Blink/V8 engine.

## Crash Type
{crash_type}

## ASan / Crash Log (truncated)
```
{log_snippet}
```

## Fuzz HTML that triggered it (truncated)
```html
{html_snippet}
```

Respond ONLY with valid JSON (no markdown, no preamble):
{{
  "summary": "<1-2 sentence plain explanation of what crashed and why>",
  "severity": "critical|high|medium|low",
  "root_cause": "<technical root cause: which C++ object/path is likely corrupted>",
  "affected_component": "<e.g. Blink LayoutNG, V8 JIT, WebGL Command Buffer, etc.>",
  "exploitation_potential": "<none|theoretical|possible|likely — brief reason>",
  "next_mutations": [
    "<concrete mutation suggestion 1>",
    "<concrete mutation suggestion 2>",
    "<concrete mutation suggestion 3>"
  ],
  "cve_similar": "<similar known CVE or 'no known similar CVE'>",
  "interesting": true_or_false
}}"""

    try:
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text.strip()
        # Strip any accidental markdown fences
        raw = re.sub(r'^```[a-z]*\n?', '', raw).rstrip('`').strip()
        return json.loads(raw)
    except json.JSONDecodeError as e:
        return {"summary": f"AI returned non-JSON: {e}", "severity": "unknown",
                "root_cause": "parse error", "next_mutations": [], "cve_similar": "N/A",
                "interesting": False}
    except Exception as e:
        return {"summary": f"Claude API error: {e}", "severity": "unknown",
                "root_cause": "api error", "next_mutations": [], "cve_similar": "N/A",
                "interesting": False}


# ── Telegram Sender ──────────────────────────────────────
def tg_send(text: str, parse_mode="HTML", disable_preview=True) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[TG SKIP] No token/chat_id set.\n{text}\n")
        return False
    try:
        r = httpx.post(
            f"{TELEGRAM_API}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": disable_preview,
            },
            timeout=15,
        )
        data = r.json()
        if not data.get("ok"):
            print(f"[TG ERROR] {data}")
            return False
        return True
    except Exception as e:
        print(f"[TG EXCEPTION] {e}")
        return False

def tg_send_file(path: Path, caption: str = "") -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        with open(path, 'rb') as f:
            r = httpx.post(
                f"{TELEGRAM_API}/sendDocument",
                data={"chat_id": TELEGRAM_CHAT_ID, "caption": caption[:1024], "parse_mode": "HTML"},
                files={"document": (path.name, f, "text/plain")},
                timeout=30,
            )
        return r.json().get("ok", False)
    except Exception as e:
        print(f"[TG FILE ERROR] {e}")
        return False


# ── Main ─────────────────────────────────────────────────
def main():
    now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    crashes = list(CRASH_DIR.glob("*.log")) if CRASH_DIR.exists() else []
    logs    = list(LOG_DIR.glob("*.log"))   if LOG_DIR.exists()   else []

    total_runs    = len(logs) + len(crashes)
    total_crashes = len(crashes)
    seen_hashes   = set()
    unique_crashes = []

    print(f"[Reporter] Found {total_crashes} crash logs, {len(logs)} run logs")

    # ── Collect & deduplicate crashes ──
    for log_path in sorted(crashes):
        log_text = log_path.read_text(errors='replace')
        crash_type, emoji = detect_crash_type(log_text)
        frames = extract_stack_frames(log_text)
        h = dedup_hash(crash_type, frames)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        # Find matching HTML if exists
        html_path = CRASH_DIR / log_path.name.replace('.log', '.html')
        html_text = html_path.read_text(errors='replace') if html_path.exists() else ""

        unique_crashes.append({
            "hash":       h,
            "log_path":   log_path,
            "html_path":  html_path if html_path.exists() else None,
            "crash_type": crash_type,
            "emoji":      emoji,
            "frames":     frames,
            "log_text":   log_text,
            "html_text":  html_text,
        })

    # Sort by severity
    unique_crashes.sort(key=lambda c: SEVERITY_ORDER.get(c["emoji"], 99))

    print(f"[Reporter] {len(unique_crashes)} unique crashes after deduplication")

    # ── AI Analysis for each unique crash ──
    analyses = []
    for crash in unique_crashes:
        print(f"[AI] Analyzing {crash['crash_type']} ({crash['hash']})...")
        analysis = analyze_with_claude(
            crash_type   = crash["crash_type"],
            log_snippet  = truncate(crash["log_text"],   MAX_CRASH_LOG_CHARS),
            html_snippet = truncate(crash["html_text"],  2000),
        )
        crash["analysis"] = analysis
        analyses.append({**crash, "log_text": None, "html_text": None})  # no big text in summary

        # Save JSON triage
        triage_out = TRIAGE_DIR / f"triage_{crash['hash']}.json"
        triage_out.write_text(json.dumps({
            "hash":      crash["hash"],
            "type":      crash["crash_type"],
            "severity":  analysis.get("severity","unknown"),
            "analysis":  analysis,
            "frames":    crash["frames"],
            "log_file":  str(crash["log_path"]),
        }, indent=2))
        time.sleep(0.5)   # be nice to API

    # ── Build Telegram messages ──

    # 1. Header message
    if total_crashes == 0:
        status_line = "✅ <b>No crashes detected</b> — engine looks stable"
        header_emoji = "🟢"
    elif any(c["emoji"] == "🔴" for c in unique_crashes):
        status_line = f"🚨 <b>CRITICAL crashes found!</b> — immediate review needed"
        header_emoji = "🔴"
    else:
        status_line = f"⚠️ <b>{len(unique_crashes)} crash(es) detected</b>"
        header_emoji = "🟡"

    header_msg = f"""{header_emoji} <b>Chromium Fuzzer Report</b>
🕐 {now}
📦 Repo: <code>{GITHUB_REPO}</code>

{status_line}

📊 <b>Stats</b>
├ HTML files generated : <code>{HTML_COUNT}</code>
├ Total executions     : <code>{total_runs}</code>
├ Crashes found        : <code>{total_crashes}</code>
└ Unique crash types   : <code>{len(unique_crashes)}</code>

🔗 <a href="{GITHUB_RUN_URL}">View GitHub Actions Run</a>"""

    tg_send(header_msg)
    time.sleep(0.5)

    # 2. Per-crash detail messages
    for i, crash in enumerate(unique_crashes[:8]):   # max 8 detailed reports
        a = crash.get("analysis", {})
        sev_map = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM",
                   "low": "⚪ LOW", "unknown": "❓ UNKNOWN"}
        sev = sev_map.get(a.get("severity","unknown"), "❓")

        mutations = a.get("next_mutations", [])
        mut_lines = "\n".join(f"  • {m}" for m in mutations[:3]) if mutations else "  • N/A"

        frames_preview = "\n".join(f"  <code>#{j} {f[:70]}</code>" for j, f in enumerate(crash["frames"][:5]))

        detail_msg = f"""━━━━━━━━━━━━━━━━━━━━━━━━
{crash['emoji']} <b>Crash #{i+1}</b>  |  <code>{crash['hash']}</code>

<b>Type:</b> <code>{crash['crash_type']}</code>
<b>Severity:</b> {sev}
<b>Component:</b> <code>{a.get('affected_component','unknown')}</code>

🧠 <b>AI Analysis:</b>
{a.get('summary','N/A')}

🔍 <b>Root Cause:</b>
<code>{a.get('root_cause','unknown')[:200]}</code>

💣 <b>Exploitation Potential:</b>
{a.get('exploitation_potential','unknown')}

🔗 <b>Similar CVE:</b>
{a.get('cve_similar','N/A')}

📚 <b>Top Stack Frames:</b>
{frames_preview}

🧬 <b>Suggested Next Mutations:</b>
{mut_lines}"""

        tg_send(truncate(detail_msg, MAX_TG_MSG_CHARS))

        # Send the actual crash HTML as file attachment
        if crash.get("html_path") and crash["html_path"].exists():
            tg_send_file(
                crash["html_path"],
                caption=f"🗂 PoC HTML — {crash['crash_type']} ({crash['hash']})"
            )
        time.sleep(0.5)

    # 3. Summary / recommendations message
    if unique_crashes:
        critical_count = sum(1 for c in unique_crashes if c.get("analysis",{}).get("severity") == "critical")
        interesting    = [c for c in unique_crashes if c.get("analysis",{}).get("interesting")]

        recs = []
        for c in unique_crashes[:3]:
            for m in c.get("analysis",{}).get("next_mutations",[])[:1]:
                recs.append(f"• {m}")

        recs_text = "\n".join(recs) if recs else "• Continue fuzzing with same corpus"

        summary_msg = f"""📋 <b>Fuzzer Run Summary</b>

🔴 Critical : <code>{critical_count}</code>
🔬 Interesting unique crashes : <code>{len(interesting)}</code>

🎯 <b>Recommended Next Steps:</b>
{recs_text}

💾 Full triage JSONs available as GitHub Actions artifacts.
🔁 Next scheduled run: in 6 hours."""

        tg_send(summary_msg)

    else:
        tg_send(f"""✅ <b>All Clear</b>

No crashes detected in this fuzzer run.
The generated corpus ({HTML_COUNT} HTMLs) will be saved for the next run.

🔁 Next scheduled run: in 6 hours.""")

    print(f"[Reporter] Done. Sent Telegram messages for {len(unique_crashes)} unique crashes.")


if __name__ == "__main__":
    main()
