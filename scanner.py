import os
import sys
import re
import datetime
from dotenv import load_dotenv
from colorama import init, Fore, Style
import google.genai as genai

init(autoreset=True)
load_dotenv()

# ── Color helpers ─────────────────────────────────────────────────────────────

def log(msg, level="info"):
    colors = {"info": Fore.CYAN, "success": Fore.GREEN, "warning": Fore.YELLOW, "error": Fore.RED}
    print(colors.get(level, Fore.WHITE) + f"[{level.upper()}] {msg}")

def banner():
    print()
    print(Fore.RED + Style.BRIGHT + "╔══════════════════════════════════════════════════╗")
    print(Fore.RED + Style.BRIGHT + "║      AI Security Scanner  —  Powered by Gemini   ║")
    print(Fore.RED + Style.BRIGHT + "╚══════════════════════════════════════════════════╝")
    print()

def divider():
    print(Fore.WHITE + Style.DIM + "  " + "─" * 54)
    print()

# ── Gemini prompt ─────────────────────────────────────────────────────────────

SECURITY_PROMPT = """
You are an expert cybersecurity analyst performing a code security audit.

Analyze the provided code and identify ALL security vulnerabilities.

For EACH vulnerability found, format your output EXACTLY like this:

[VULNERABILITY #N]
Type       : <vulnerability type, e.g. SQL Injection>
Severity   : <CRITICAL | HIGH | MEDIUM | LOW>
CWE        : <CWE-ID, e.g. CWE-89>
Line       : <line number or "unknown">
Why        : <one sentence explaining why this is vulnerable>
Impact     : <one sentence describing the real-world impact>
Fix        :
<provide the corrected code snippet only, no extra explanation>

After listing all vulnerabilities, add this section:

[SUMMARY]
Total      : <number>
Critical   : <number>
High       : <number>
Medium     : <number>
Low        : <number>
Risk Level : <CRITICAL | HIGH | MEDIUM | LOW | SAFE>
Verdict    : <one sentence overall assessment>

If no vulnerabilities are found, respond with:
[SUMMARY]
Total      : 0
Risk Level : SAFE
Verdict    : No vulnerabilities detected. Code appears secure.

Code to analyze:
```
{code}
```
"""

# ── Response parser ───────────────────────────────────────────────────────────

def parse_response(text):
    """Parse Gemini structured response into a dict."""
    vulnerabilities = []
    summary = {}

    vuln_blocks = re.split(r'\[VULNERABILITY #\d+\]', text)
    summary_split = re.split(r'\[SUMMARY\]', text, flags=re.IGNORECASE)

    # Parse vulnerabilities
    for block in vuln_blocks[1:]:  # skip text before first vuln
        if '[SUMMARY]' in block.upper():
            block = block[:block.upper().index('[SUMMARY]')]
        vuln = {}
        fix_match = re.search(r'Fix\s*:\s*\n([\s\S]+?)(?=\n[A-Z][a-z]|\Z)', block, re.IGNORECASE)
        if fix_match:
            vuln['fix'] = fix_match.group(1).strip()
            block_no_fix = block[:fix_match.start()]
        else:
            vuln['fix'] = ''
            block_no_fix = block

        for line in block_no_fix.splitlines():
            if ':' in line:
                key, _, val = line.partition(':')
                vuln[key.strip().lower().replace(' ', '_')] = val.strip()
        vulnerabilities.append(vuln)

    # Parse summary
    if len(summary_split) > 1:
        sum_block = summary_split[-1]
        for line in sum_block.splitlines():
            if ':' in line:
                key, _, val = line.partition(':')
                summary[key.strip().lower().replace(' ', '_')] = val.strip()

    return vulnerabilities, summary

# ── Terminal printer ──────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.YELLOW + Style.BRIGHT,
    "MEDIUM":   Fore.CYAN,
    "LOW":      Fore.WHITE + Style.DIM,
    "SAFE":     Fore.GREEN + Style.BRIGHT,
}

def print_terminal(vulnerabilities, summary, raw_text):
    divider()
    print(Style.BRIGHT + "  VULNERABILITY REPORT\n")

    if not vulnerabilities:
        print(Fore.GREEN + Style.BRIGHT + "  [PASS] No vulnerabilities detected!\n")
    else:
        for i, v in enumerate(vulnerabilities, 1):
            sev = v.get('severity', 'UNKNOWN').upper()
            sev_color = SEV_COLORS.get(sev, Fore.WHITE)
            print(Fore.RED + Style.BRIGHT + f"  [VULNERABILITY #{i}]")
            print(f"  {Fore.WHITE + Style.DIM}Type     {Style.RESET_ALL}: {v.get('type','')}")
            print(f"  {Fore.WHITE + Style.DIM}Severity {Style.RESET_ALL}: {sev_color}{sev}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE + Style.DIM}CWE      {Style.RESET_ALL}: {v.get('cwe','')}")
            print(f"  {Fore.WHITE + Style.DIM}Line     {Style.RESET_ALL}: {v.get('line','')}")
            print(f"  {Fore.WHITE + Style.DIM}Why      {Style.RESET_ALL}: {v.get('why','')}")
            print(f"  {Fore.WHITE + Style.DIM}Impact   {Style.RESET_ALL}: {v.get('impact','')}")
            if v.get('fix'):
                print(f"  {Fore.WHITE + Style.DIM}Fix      {Style.RESET_ALL}:")
                for fl in v['fix'].splitlines():
                    print(Fore.GREEN + f"    {fl}")
            print()

    divider()
    print(Style.BRIGHT + "  SCAN SUMMARY\n")
    risk = summary.get('risk_level', 'UNKNOWN').upper()
    risk_color = SEV_COLORS.get(risk, Fore.WHITE)
    print(f"  {Fore.WHITE + Style.DIM}Total     {Style.RESET_ALL}: {summary.get('total','0')}")
    print(f"  {Fore.RED}Critical  {Style.RESET_ALL}: {summary.get('critical','0')}")
    print(f"  {Fore.YELLOW}High      {Style.RESET_ALL}: {summary.get('high','0')}")
    print(f"  {Fore.CYAN}Medium    {Style.RESET_ALL}: {summary.get('medium','0')}")
    print(f"  {Fore.WHITE + Style.DIM}Low       {Style.RESET_ALL}: {summary.get('low','0')}")
    print(f"  {Fore.WHITE + Style.DIM}Risk      {Style.RESET_ALL}: {risk_color}{risk}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE + Style.DIM}Verdict   {Style.RESET_ALL}: {Style.BRIGHT}{summary.get('verdict','')}{Style.RESET_ALL}")
    print()

# ── HTML report generator ─────────────────────────────────────────────────────

SEV_HTML = {
    "CRITICAL": ("#ff4d4d", "#2d0000"),
    "HIGH":     ("#ffaa00", "#2d1a00"),
    "MEDIUM":   ("#4da6ff", "#001a2d"),
    "LOW":      ("#aaaaaa", "#1a1a1a"),
    "SAFE":     ("#00cc66", "#001a0d"),
}

def esc(text):
    return str(text).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def generate_html(vulnerabilities, summary, code_path, code, scanned_at):
    risk = summary.get('risk_level', 'UNKNOWN').upper()
    risk_color, risk_bg = SEV_HTML.get(risk, ("#aaa", "#111"))
    total = summary.get('total', str(len(vulnerabilities)))

    vuln_cards = ""
    for i, v in enumerate(vulnerabilities, 1):
        sev = v.get('severity', 'UNKNOWN').upper()
        s_color, s_bg = SEV_HTML.get(sev, ("#aaa","#111"))
        fix_html = f'<pre class="fix-code">{esc(v.get("fix",""))}</pre>' if v.get("fix") else ""
        vuln_cards += f"""
        <div class="vuln-card" data-sev="{sev}">
          <div class="vuln-header">
            <span class="vuln-num">#{i}</span>
            <span class="vuln-type">{esc(v.get('type','Unknown'))}</span>
            <span class="sev-badge" style="background:{s_bg};color:{s_color};border:1px solid {s_color}22">{sev}</span>
            <span class="cwe-badge">{esc(v.get('cwe',''))}</span>
          </div>
          <div class="vuln-body">
            <div class="meta-row"><span class="meta-key">Line</span><span class="meta-val">{esc(v.get('line','unknown'))}</span></div>
            <div class="meta-row"><span class="meta-key">Why</span><span class="meta-val">{esc(v.get('why',''))}</span></div>
            <div class="meta-row"><span class="meta-key">Impact</span><span class="meta-val">{esc(v.get('impact',''))}</span></div>
            <div class="fix-section">
              <div class="fix-label">Recommended Fix</div>
              {fix_html}
            </div>
          </div>
        </div>"""

    if not vulnerabilities:
        vuln_cards = '<div class="safe-msg">&#10003; No vulnerabilities detected — code appears secure.</div>'

    filter_btns = ""
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        count = sum(1 for v in vulnerabilities if v.get('severity','').upper() == sev)
        if count:
            sc, _ = SEV_HTML[sev]
            filter_btns += f'<button class="filter-btn" data-filter="{sev}" style="border-color:{sc};color:{sc}" onclick="filterCards(\'{sev}\')">{sev} ({count})</button>'
    if filter_btns:
        filter_btns = f'<button class="filter-btn active" data-filter="ALL" onclick="filterCards(\'ALL\')">All ({len(vulnerabilities)})</button>' + filter_btns

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Scan — {esc(os.path.basename(code_path))}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0d0d0f;
    --surface: #141418;
    --border: #2a2a32;
    --text: #e8e8f0;
    --muted: #666680;
    --accent: #ff4d4d;
    --green: #00cc66;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Syne', sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; }}

  /* ── header ── */
  .header {{ padding: 2.5rem 2rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 1.5rem; flex-wrap: wrap; }}
  .header-icon {{ font-size: 2rem; }}
  .header-title {{ font-size: 1.6rem; font-weight: 800; letter-spacing: -0.5px; }}
  .header-sub {{ font-size: 0.8rem; color: var(--muted); font-family: var(--mono); margin-top: 4px; }}
  .risk-pill {{ margin-left: auto; padding: 6px 20px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; font-family: var(--mono); letter-spacing: 1px; border: 1px solid; }}

  /* ── summary bar ── */
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px,1fr)); gap: 1px; background: var(--border); border-bottom: 1px solid var(--border); }}
  .stat-cell {{ background: var(--surface); padding: 1.2rem 1.5rem; }}
  .stat-num {{ font-size: 2rem; font-weight: 800; font-family: var(--mono); line-height: 1; }}
  .stat-lbl {{ font-size: 0.7rem; color: var(--muted); margin-top: 4px; letter-spacing: 1px; text-transform: uppercase; }}
  .stat-critical .stat-num {{ color: #ff4d4d; }}
  .stat-high .stat-num {{ color: #ffaa00; }}
  .stat-medium .stat-num {{ color: #4da6ff; }}
  .stat-low .stat-num {{ color: #888; }}
  .stat-total .stat-num {{ color: var(--text); }}

  /* ── verdict ── */
  .verdict {{ padding: 1rem 2rem; background: var(--surface); border-bottom: 1px solid var(--border); font-size: 0.85rem; color: var(--muted); }}
  .verdict strong {{ color: var(--text); }}

  /* ── filters ── */
  .filter-bar {{ padding: 1rem 2rem; display: flex; gap: 8px; flex-wrap: wrap; border-bottom: 1px solid var(--border); }}
  .filter-btn {{ padding: 5px 14px; border-radius: 999px; background: transparent; font-size: 0.72rem; font-family: var(--mono); font-weight: 600; letter-spacing: 0.5px; cursor: pointer; border: 1px solid var(--border); color: var(--muted); transition: all 0.15s; }}
  .filter-btn:hover, .filter-btn.active {{ background: rgba(255,255,255,0.06); color: var(--text); border-color: var(--muted); }}

  /* ── main ── */
  .main {{ padding: 1.5rem 2rem; max-width: 1100px; }}

  /* ── vuln card ── */
  .vuln-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 1rem; overflow: hidden; transition: border-color 0.2s; }}
  .vuln-card:hover {{ border-color: #3a3a48; }}
  .vuln-header {{ display: flex; align-items: center; gap: 10px; padding: 0.9rem 1.2rem; border-bottom: 1px solid var(--border); flex-wrap: wrap; }}
  .vuln-num {{ font-family: var(--mono); font-size: 0.72rem; color: var(--muted); min-width: 24px; }}
  .vuln-type {{ font-weight: 700; font-size: 0.95rem; flex: 1; }}
  .sev-badge {{ padding: 3px 12px; border-radius: 999px; font-size: 0.68rem; font-family: var(--mono); font-weight: 600; letter-spacing: 1px; }}
  .cwe-badge {{ font-family: var(--mono); font-size: 0.7rem; color: var(--muted); background: #1e1e26; padding: 3px 10px; border-radius: 4px; }}

  .vuln-body {{ padding: 1rem 1.2rem; }}
  .meta-row {{ display: flex; gap: 1rem; margin-bottom: 0.6rem; font-size: 0.85rem; }}
  .meta-key {{ color: var(--muted); font-family: var(--mono); font-size: 0.75rem; min-width: 60px; padding-top: 2px; }}
  .meta-val {{ color: var(--text); line-height: 1.5; }}

  .fix-section {{ margin-top: 1rem; }}
  .fix-label {{ font-size: 0.7rem; font-family: var(--mono); color: var(--green); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 6px; }}
  .fix-code {{ background: #0a1a10; border: 1px solid #1a3a20; border-radius: 6px; padding: 0.9rem 1rem; font-family: var(--mono); font-size: 0.78rem; color: #7dff9e; overflow-x: auto; white-space: pre; line-height: 1.6; }}

  /* ── source code block ── */
  .source-section {{ margin-top: 2rem; }}
  .source-label {{ font-size: 0.75rem; font-family: var(--mono); color: var(--muted); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px; }}
  .source-code {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-family: var(--mono); font-size: 0.75rem; color: #aaa; overflow-x: auto; white-space: pre; max-height: 360px; overflow-y: auto; line-height: 1.6; }}

  /* ── safe ── */
  .safe-msg {{ padding: 2rem; text-align: center; color: var(--green); font-size: 1.1rem; font-weight: 700; border: 1px solid #1a3a20; border-radius: 10px; background: #0a1a10; }}

  /* ── footer ── */
  .footer {{ padding: 1.5rem 2rem; border-top: 1px solid var(--border); font-size: 0.72rem; color: var(--muted); font-family: var(--mono); }}
</style>
</head>
<body>

<div class="header">
  <div class="header-icon">&#128272;</div>
  <div>
    <div class="header-title">Security Scan Report</div>
    <div class="header-sub">{esc(code_path)} &nbsp;·&nbsp; {scanned_at} &nbsp;·&nbsp; Gemini 2.5 Flash</div>
  </div>
  <div class="risk-pill" style="background:{risk_bg};color:{risk_color};border-color:{risk_color}44">{risk}</div>
</div>

<div class="summary">
  <div class="stat-cell stat-total"><div class="stat-num">{esc(total)}</div><div class="stat-lbl">Total</div></div>
  <div class="stat-cell stat-critical"><div class="stat-num">{esc(summary.get('critical','0'))}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat-cell stat-high"><div class="stat-num">{esc(summary.get('high','0'))}</div><div class="stat-lbl">High</div></div>
  <div class="stat-cell stat-medium"><div class="stat-num">{esc(summary.get('medium','0'))}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat-cell stat-low"><div class="stat-num">{esc(summary.get('low','0'))}</div><div class="stat-lbl">Low</div></div>
</div>

<div class="verdict"><strong>Verdict:</strong> {esc(summary.get('verdict',''))}</div>

{'<div class="filter-bar">' + filter_btns + '</div>' if filter_btns else ''}

<div class="main">
  {vuln_cards}

  <div class="source-section">
    <div class="source-label">Scanned Source Code</div>
    <pre class="source-code">{esc(code)}</pre>
  </div>
</div>

<div class="footer">Generated by AI Security Scanner &nbsp;·&nbsp; Powered by Google Gemini &nbsp;·&nbsp; {scanned_at}</div>

<script>
function filterCards(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`[data-filter="${{sev}}"]`).classList.add('active');
  document.querySelectorAll('.vuln-card').forEach(card => {{
    card.style.display = (sev === 'ALL' || card.dataset.sev === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""
    return html

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    banner()

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        log("GOOGLE_API_KEY not found in .env file", "error")
        log("Add to .env: GOOGLE_API_KEY=your_key_here", "info")
        sys.exit(1)

    if len(sys.argv) < 2:
        log("Usage: python scanner.py <file_path>", "warning")
        log("Example: python scanner.py vulnerable_code.py", "info")
        sys.exit(1)

    code_path = sys.argv[1]
    if not os.path.exists(code_path):
        log(f"File not found: {code_path}", "error")
        sys.exit(1)

    with open(code_path, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    log(f"Target       : {code_path}", "info")
    log(f"Lines        : {code.count(chr(10)) + 1}", "info")
    log("Connecting to Gemini API...", "info")

    try:
        client = genai.Client(api_key=api_key)
        prompt = SECURITY_PROMPT.format(code=code)

        log("Scanning for vulnerabilities...", "info")
        print()

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        raw_text = response.text
        log("Scan complete!", "success")

        # Parse response
        vulnerabilities, summary = parse_response(raw_text)

        # Print to terminal
        print_terminal(vulnerabilities, summary, raw_text)

        # Save HTML report
        scanned_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = generate_html(vulnerabilities, summary, code_path, code, scanned_at)

        base = os.path.splitext(os.path.basename(code_path))[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"scan_report_{base}_{timestamp}.html"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        log(f"HTML report saved: {report_path}", "success")
        log(f"Open it in your browser to view the full report.", "info")
        print()

    except Exception as e:
        log(f"Gemini API error: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()