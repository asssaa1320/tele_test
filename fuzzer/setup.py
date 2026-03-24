#!/usr/bin/env python3
"""
setup.py — Interactive setup for Chromium Fuzzer GitHub repo
Helps you:
  1. Validate Telegram bot token
  2. Create GitHub secrets via gh CLI
  3. Verify repo structure
"""
import subprocess, sys, os, json, urllib.request

def run(cmd, capture=True):
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    return r.stdout.strip(), r.stderr.strip(), r.returncode

def check(label, ok, detail=""):
    mark = "✅" if ok else "❌"
    print(f"  {mark}  {label}", f"({detail})" if detail else "")
    return ok

def test_telegram(token, chat_id):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = json.dumps({
        "chat_id": chat_id,
        "text": "🤖 Chromium Fuzzer — setup test message. If you see this, Telegram is configured correctly!",
        "parse_mode": "HTML"
    }).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        return result.get("ok", False), result
    except Exception as e:
        return False, str(e)

def main():
    print("\n" + "═"*60)
    print("  Chromium Fuzzer — GitHub Actions Setup")
    print("═"*60 + "\n")

    # ── Check gh CLI ──
    _, _, rc = run("gh --version")
    if not check("GitHub CLI (gh) installed", rc == 0, "brew install gh  OR  apt install gh"):
        print("\n  Install gh CLI: https://cli.github.com/")
        sys.exit(1)

    # ── Check git repo ──
    out, _, rc = run("git remote get-url origin")
    if not check("Git repository with remote", rc == 0, out):
        print("\n  Initialize a git repo first: git init && git remote add origin <url>")
        sys.exit(1)
    repo_url = out

    # ── Get secrets ──
    print("\n  Enter your secrets (input hidden in terminal):\n")

    import getpass
    tg_token  = getpass.getpass("  Telegram Bot Token (from @BotFather): ").strip()
    tg_chat   = input("  Telegram Chat ID (your user ID or group ID): ").strip()
    anth_key  = getpass.getpass("  Anthropic API Key (sk-ant-...): ").strip()

    # ── Test Telegram ──
    print("\n  Testing Telegram connection...")
    ok, result = test_telegram(tg_token, tg_chat)
    if not check("Telegram bot can send messages", ok, str(result)[:80]):
        print("\n  Tips:")
        print("  • Get token from @BotFather")
        print("  • Get your chat ID from @userinfobot")
        print("  • For groups: add bot to group, then use negative ID like -100xxx")
        sys.exit(1)

    # ── Set GitHub secrets ──
    print("\n  Setting GitHub secrets...")
    secrets = {
        "TELEGRAM_BOT_TOKEN":  tg_token,
        "TELEGRAM_CHAT_ID":    tg_chat,
        "ANTHROPIC_API_KEY":   anth_key,
    }
    all_ok = True
    for name, val in secrets.items():
        _, err, rc = run(f'gh secret set {name} --body "{val}"')
        all_ok &= check(f"gh secret set {name}", rc == 0, err[:60] if err else "")

    if not all_ok:
        print("\n  Make sure you're authenticated: gh auth login")
        sys.exit(1)

    # ── Verify repo structure ──
    print("\n  Verifying repo structure...")
    required = [
        ".github/workflows/fuzzer.yml",
        "fuzzer/fuzzer.py",
        "fuzzer/ai_reporter.py",
        "fuzzer/crash_triage.py",
    ]
    for path in required:
        check(path, os.path.exists(path))

    print(f"""
{'═'*60}
  ✅  Setup complete!

  Next steps:
  1. git add . && git commit -m 'Add Chromium fuzzer workflow'
  2. git push origin main
  3. Go to GitHub Actions → run 'Chromium Semantic Fuzzer' manually
     (or wait for scheduled run at 00:00, 06:00, 12:00, 18:00 UTC)

  Telegram notifications will arrive at chat: {tg_chat}
{'═'*60}
""")

if __name__ == "__main__":
    main()
