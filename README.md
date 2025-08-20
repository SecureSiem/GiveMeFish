# 🛠 Installation
    # 1) Install dependencies globally (or use pipx if you prefer isolation)
    pip install -r requirements.txt

    # 2) Put your keys into .env (or export them in your shell)

    # 3) Run on an .eml
    python3 GiveMeFish.py -E /path/to/message.eml

Optional flags:

--verbose → also prints the full JSON report to stdout

-o report.json → saves the full JSON report

--no-network → skip DNS/VT/GSB/WHOIS/TLS (offline mode)

--auto-upload → if an attachment hash is unknown to VT, upload it (use with caution)

# Examples:
    python3 GiveMeFish.py -E sample.eml
    python3 GiveMeFish.py -E sample.eml --verbose -o report.json
    python3 GiveMeFish.py -E sample.eml --auto-upload


# GiveMeFish – Advanced Phishing Email Analysis

**GiveMeFish** ingests a raw `.eml` and performs deep phishing analysis:
- SPF / DKIM verification and DMARC policy lookup (DNS-based)
- URL extraction, redirect chain, TLS cert peek, WHOIS/age
- VirusTotal for URLs & attachment hashes
- Google Safe Browsing (v4)
- Attachment extraction, hashing, macro detection (oletools)
- Optional OpenAI “second opinion”
- Heuristic scoring and rich, human-readable report + JSON

## Quick Start
```bash
pip install -r requirements.txt
cp .env.example .env  # then fill your keys
python3 GiveMeFish.py -E /path/to/email.eml
```
# Environment
Create .env:

    VIRUSTOTAL_API_KEY=your_key
    GOOGLE_SAFE_BROWSING_KEY=your_key
    OPENAI_API_KEY=your_key   # optional

# Usage
    python3 GiveMeFish.py -E sample.eml [--verbose] [-o report.json] [--no-network] [--auto-upload]

# Notes

DNS queries require outbound DNS/HTTPS connectivity.

Some providers use multiple Received: lines; SPF results depend on parsing the correct hop IP.

Safety: --auto-upload will upload attachments to VirusTotal (public intelligence). Use in lab environments or with permission.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

