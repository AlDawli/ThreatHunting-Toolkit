# ThreatHunting-Toolkit

Setup (3 steps)
1 — Install dependencies
bashcd threat_hunting_toolkit
pip install -r requirements.txt
2 — Get your VirusTotal API key

Register free at virustotal.com/gui/join-us
Free tier gives you 500 lookups/day, 4/minute — the code handles the rate-limiting automatically

bashcp .env.example .env
# Open .env and paste your key:  VT_API_KEY=your_key_here
3 — Run
bashpython main.py           # interactive prompt
python main.py --web     # → http://localhost:5000
python main.py --desktop # Tkinter GUI

What's inside each module
FileRolecore/ioc_detector.pyRegex-based auto-detection — IP, MD5/SHA1/SHA256, domain, URL, emailcore/virustotal.pyVT API v3 wrapper — hash, domain, IP, URL (polls for new URL scans)core/database.pySQLite — searches table (full history) + iocs table (watchlist)core/report_generator.pyfpdf2-based PDF with summary, watchlist table, detection detail cardsinterfaces/web/app.pyFlask REST API — 8 endpoints consumed by the dashboardinterfaces/web/templates/index.htmlDark SOC dashboard — tabs, verdict banners, detection tables, export buttoninterfaces/desktop/app.pyTkinter ttk.Notebook — same 7 tabs, threaded VT calls so UI never freezes

Natural next extensions to try

Bulk IOC upload — parse a .txt or .csv and loop check_* with a progress bar
AbuseIPDB integration — second opinion on IP reputation (free API, similar pattern to VT)
Scheduled re-scan — use schedule or APScheduler to re-check watchlist IOCs daily
MISP export — serialize the IOC watchlist to MISP-compatible JSON for threat sharing
