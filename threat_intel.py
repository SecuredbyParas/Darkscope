"""
threat_intel.py
Static reference content used to power the awareness/education side of the
app: MITRE ATT&CK technique descriptions and Verizon DBIR-style statistics.

These figures are illustrative, rounded summaries inspired by publicly
published Verizon DBIR themes (credential-driven breaches, phishing,
stolen-credential reuse) for TEACHING purposes in this simulator. They are
not pulled verbatim from any report and should not be cited as the report's
exact numbers.
"""

MITRE_TECHNIQUES = {
    "T1589.001": {
        "name": "Gather Victim Identity Info: Credentials",
        "tactic": "Reconnaissance",
        "summary": "Adversaries collect leaked email/password pairs from "
                    "breach dumps and marketplaces to build target lists "
                    "before an intrusion.",
    },
    "T1589.002": {
        "name": "Gather Victim Identity Info: Email Addresses",
        "tactic": "Reconnaissance",
        "summary": "Harvested email addresses are used for phishing, "
                    "spam, and account-enumeration campaigns.",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "summary": "Leaked passwords seed wordlists used to guess "
                    "credentials on other services the victim may use.",
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "summary": "A single leaked password is tried across many "
                    "accounts/services, betting on password reuse.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "summary": "Stolen-but-valid credentials let an attacker log in "
                    "looking like a legitimate user, bypassing many "
                    "perimeter defenses.",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access / Persistence",
        "summary": "Reused credentials are tried against cloud/SaaS "
                    "logins (email, storage, SSO) where MFA is absent.",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "summary": "Personal details from a leak make follow-up phishing "
                    "emails far more convincing and targeted.",
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "summary": "Misconfigured cloud storage is a common source of "
                    "large-scale credential and PII leaks.",
    },
}

# Illustrative summary stats for the dashboard charts (educational, rounded)
DBIR_STATS = {
    "breaches_involving_credentials_pct": 61,
    "breaches_involving_phishing_pct": 36,
    "breaches_involving_human_element_pct": 68,
    "time_to_click_phish_minutes_median": 21,
    "orgs_with_mfa_gap_pct": 47,
}

DBIR_YEARLY_TREND = [
    {"year": 2020, "credential_breaches_pct": 58},
    {"year": 2021, "credential_breaches_pct": 61},
    {"year": 2022, "credential_breaches_pct": 63},
    {"year": 2023, "credential_breaches_pct": 59},
    {"year": 2024, "credential_breaches_pct": 61},
]


def get_techniques_for(codes_csv: str):
    """Turn 'T1589.001,T1110.001' into a list of technique detail dicts."""
    codes = [c.strip() for c in codes_csv.split(",") if c.strip()]
    return [
        {"code": c, **MITRE_TECHNIQUES.get(c, {
            "name": "Unknown Technique",
            "tactic": "N/A",
            "summary": "No description available.",
        })}
        for c in codes
    ]
