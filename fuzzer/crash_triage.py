#!/usr/bin/env python3
"""
crash_triage.py — Analyze ASan crash logs and suggest next mutations.
Usage:  python3 crash_triage.py crashes/CRASH_*.log
"""

import sys, re, json, hashlib, textwrap
from pathlib import Path

ASAN_PATTERNS = {
    r"heap-use-after-free":            "USE-AFTER-FREE",
    r"heap-buffer-overflow":           "HEAP-BOF",
    r"stack-buffer-overflow":          "STACK-BOF",
    r"global-buffer-overflow":         "GLOBAL-BOF",
    r"use-of-uninitialized-value":     "UNINIT-VALUE",
    r"double-free":                    "DOUBLE-FREE",
    r"attempting free on address":     "INVALID-FREE",
    r"out-of-bounds":                  "OOB-ACCESS",
    r"SEGV on unknown address 0x0":    "NULL-DEREF",
    r"SEGV on unknown address":        "SEGFAULT",
    r"CHECK\((.+?)\) failed":          "CHECK-FAIL",
    r"DCHECK\((.+?)\) failed":         "DCHECK-FAIL",
    r"AddressSanitizer: (.+) on":      "ASAN-GENERIC",
}

MUTATION_SUGGESTIONS = {
    "USE-AFTER-FREE": [
        "→ Remove element mid-animation frame using requestAnimationFrame callback",
        "→ Call node.remove() inside a MutationObserver triggered by that node",
        "→ Transfer ArrayBuffer to Worker, then try postMessage again from main thread",
        "→ detach shadow root host while connectedCallback is firing",
    ],
    "HEAP-BOF": [
        "→ Use extreme CSS lengths: width: 999999999px; height: -1px",
        "→ Create ArrayBuffer(0) and write to index 0",
        "→ Use canvas.drawImage with src/dst rects of Integer.MAX_VALUE",
        "→ Set textContent to a string of 100k chars on a node in a flex container",
    ],
    "DOUBLE-FREE": [
        "→ adoptNode() a node that is already adopted into another document",
        "→ Call structuredClone() on a transferred ArrayBuffer",
        "→ Detach OffscreenCanvas twice via different Worker messages",
    ],
    "OOB-ACCESS": [
        "→ Atomics.load(i32, -1) — negative index",
        "→ TypedArray.set(otherArray, offset) where offset > byteLength",
        "→ DataView.getFloat64 at byteOffset = byteLength - 1 (unaligned + overrun)",
        "→ gl.readPixels with x+width > canvas.width",
    ],
    "NULL-DEREF": [
        "→ Call methods on document.querySelector('nonexistent')",
        "→ canvas.getContext('webgl3') — returns null — then call gl.createBuffer()",
        "→ Access shadowRoot of element that has no shadow root",
        "→ Use performance.getEntriesByType('nonexistent')[0].startTime",
    ],
    "CHECK-FAIL": [
        "→ Modify DOM during a paint: use ResizeObserver to change layout",
        "→ Call scrollIntoView() on a detached node",
        "→ Change display:none during a transition animation",
        "→ Remove element from inside its own animation event handler",
    ],
    "UNINIT-VALUE": [
        "→ Read Uint8Array before writing — new Uint8Array(n) is zeroed but check C++ side",
        "→ Create objects via Object.create(null) and access inherited properties",
        "→ Use structuredClone on an object with Symbol properties",
    ],
}

def extract_frames(log):
    frames = re.findall(r'#(\d+)\s+0x[0-9a-f]+ in (\S+)\s+(.+?)(?:\s+\+0x[0-9a-f]+)?$', log, re.M)
    return [(int(n), fn, loc.strip()) for n, fn, loc in frames[:20]]

def find_crash_type(log):
    for pattern, label in ASAN_PATTERNS.items():
        m = re.search(pattern, log, re.I)
        if m:
            extra = m.group(1) if m.lastindex else ""
            return label, extra
    return "UNKNOWN", ""

def interesting_frame(frames):
    keywords = ["blink::", "WebCore::", "v8::", "cc::", "viz::", "content::", "gpu::"]
    for _, fn, loc in frames:
        if any(k in fn for k in keywords):
            return fn, loc
    return (frames[0][1], frames[0][2]) if frames else ("?", "?")

def dedupe_hash(crash_type, frames):
    sig = crash_type + ''.join(fn for _, fn, _ in frames[:5])
    return hashlib.sha256(sig.encode()).hexdigest()[:12]

def triage(log_path):
    text = Path(log_path).read_text(errors='replace')
    crash_type, extra = find_crash_type(text)
    frames = extract_frames(text)
    fn, loc = interesting_frame(frames)
    h = dedupe_hash(crash_type, frames)

    print(f"\n{'═'*68}")
    print(f"  File       : {log_path}")
    print(f"  Crash type : {crash_type}  ({extra})")
    print(f"  Dedup hash : {h}")
    print(f"  Hot frame  : {fn}")
    print(f"              {loc}")
    print(f"\n  Stack trace (top 10):")
    for i, (n, fn, loc) in enumerate(frames[:10]):
        marker = "►" if i == 0 else " "
        print(f"  {marker} #{n:02d}  {fn}")
    print()

    suggestions = MUTATION_SUGGESTIONS.get(crash_type, ["→ Try more aggressive DOM/JS mutations"])
    print(f"  Next mutations to try ({crash_type}):")
    for s in suggestions:
        print(f"    {s}")
    print()

    # Write JSON report
    report = {
        "file": str(log_path),
        "crash_type": crash_type,
        "extra": extra,
        "dedup_hash": h,
        "hot_frame": fn,
        "hot_location": loc,
        "top_frames": [fn for _, fn, _ in frames[:10]],
        "mutation_hints": suggestions,
    }
    out = Path(log_path).with_suffix('.triage.json')
    out.write_text(json.dumps(report, indent=2))
    print(f"  Report saved: {out}")
    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 crash_triage.py <logfile> [logfile ...]")
        sys.exit(1)
    reports = []
    for path in sys.argv[1:]:
        try:
            r = triage(path)
            reports.append(r)
        except Exception as e:
            print(f"Error processing {path}: {e}")
    # Summary
    types = {}
    for r in reports:
        types[r["crash_type"]] = types.get(r["crash_type"], 0) + 1
    if reports:
        print(f"\n{'═'*68}")
        print(f"  SUMMARY  ({len(reports)} crashes)")
        for t, c in sorted(types.items(), key=lambda x: -x[1]):
            print(f"    {t:30s}  × {c}")
        print()
