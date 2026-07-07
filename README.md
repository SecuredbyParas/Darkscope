# DarkScope — Dark Web Exposure Awareness Simulator

**Group 8**

| Roll No. | Name | Reg. No. |
|---|---|---|
| 12503638 | Krishna | R9PV45A54 |
| 12521707 | Devender Singh Shekhawat | R9PV45A82 |
| 12500687 | Paras | R9PV45A49 |
| 12525830 | Kanika Sharma | R9PV45A93 |

## What this is

DarkScope is an educational web app that simulates how leaked credentials
surface in breach datasets, and teaches the real-world risk that exposure
creates by mapping every match to **MITRE ATT&CK** techniques, with
dashboard context inspired by **Verizon DBIR** themes.

**Every "leaked" record in this project is 100% synthetic.** The app never
touches the real internet, a real breach database, or any real person's
data — it's a safe sandbox for teaching the concept.

### Core features
- User registration & login (Flask + SQLite, hashed passwords)
- Mandatory two-factor authentication via **PyOTP** (TOTP) + **QR code**
  enrollment (compatible with Google Authenticator / Authy / any TOTP app)
- Breach-checking engine that looks an email up in a simulated breach
  dataset and returns matched sources + exposed fields
- Warning page that explains, in plain language, which MITRE ATT&CK
  techniques a given exposure enables
- Dashboard with scan history and Chart.js visualizations (credential-breach
  trend line, human-element factor breakdown)
- Threat Library page with the full MITRE technique reference and
  illustrative DBIR-style statistics
- Responsive, dark-themed UI built with HTML/CSS/Bootstrap 5

## Project structure

```
darkweb_simulator/
├── app.py                # Flask app: routes for auth, MFA, scanning, dashboard
├── database.py           # SQLite schema + synthetic breach dataset seeding
├── threat_intel.py       # MITRE ATT&CK + illustrative DBIR reference data
├── requirements.txt
├── data/                 # SQLite DB is created here on first run
├── static/
│   ├── css/style.css     # Custom dark theme ("redacted record" design system)
│   └── js/
└── templates/
    ├── base.html
    ├── index.html         # Landing page
    ├── register.html
    ├── login.html
    ├── mfa_setup.html     # QR code enrollment
    ├── mfa_verify.html    # Returning-login TOTP check
    ├── dashboard.html     # Charts + scan history
    ├── scan.html          # Email breach-check form
    ├── warning.html        # Breach result + MITRE technique breakdown
    └── learn.html          # Threat Library reference page
```

## How to run it

```bash
cd darkweb_simulator
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

Then open **http://localhost:5000** in your browser.

The SQLite database (`data/app.db`) is created and seeded automatically the
first time the app starts — no manual setup needed.

### Try it out
1. Register a new account, then scan the QR code with an authenticator app
   (Google Authenticator, Authy, Microsoft Authenticator, etc.) to finish MFA setup.
2. From the dashboard, click **Run a new scan**.
3. Try one of the demo addresses shown on the scan page (e.g.
   `demo.user1@example.com`, `alice.demo@example.com`) to see a simulated
   breach match and its MITRE ATT&CK breakdown.
   
4. Try a made-up address to see the "clean" result path.
5. Visit **Threat Library** for the full technique/stat reference.

## Responsibility mapping (for the project report)

| Responsibility | Covered by |
|---|---|
| Flask Backend — app, routes, DB connection, login, breach logic | `app.py`, `database.py` |
| SQLite + MFA — schema, breach dataset, PyOTP, QR generation, OTP verification | `database.py`, `app.py` (`mfa_setup`, `mfa_verify`) |
| User Interface — login, dashboard, warning pages, charts, responsive layout | `templates/`, `static/css/style.css` |
| Security Content — MITRE ATT&CK mapping, DBIR-style stats, awareness copy | `threat_intel.py`, `warning.html`, `learn.html` |

## Notes on academic integrity / safety

- The breach dataset is generated entirely by `database.py` at first run —
  fake `@example.com` addresses, randomly generated fake passwords, and
  fictional source names like `CollectionX-Demo`.
- DBIR-style statistics in `threat_intel.py` are rounded, illustrative figures
  written for teaching purposes — they should not be cited as the report's
  exact published numbers.
- This project is for learning/demonstration only and is not intended to
  check real email addresses against real breach data.
