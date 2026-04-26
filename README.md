# AI Security Scanner

A Python-based security vulnerability scanner powered by **Google Gemini AI**.
Scans Python source code and generates a beautiful HTML report with all findings.

## Features
- Detects SQL Injection, Command Injection, Hardcoded Secrets, Weak Hashing, and more
- Powered by Gemini 2.5 Flash AI
- Color-coded terminal output
- Auto-saves a dark-themed HTML report

## Setup

1. Clone the repo
```bash
   git clone https://github.com/YOUR_USERNAME/ai-security-scanner.git
   cd ai-security-scanner
```

2. Install dependencies
```bash
   pip install -r requirements.txt
```

3. Create a `.env` file
```
   GOOGLE_API_KEY=your_key_here
```

4. Run the scanner
```bash
   python scanner.py vulnerable.py
```

## Output
- Terminal: color-coded vulnerability report
- HTML: `scan_report_<file>_<timestamp>.html` — open in any browser

## Tech Stack
- Python 3
- Google Gemini API (`google-genai`)
- Colorama
- python-dotenv
