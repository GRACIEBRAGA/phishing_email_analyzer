"""
Phishing Email Analyzer
-----------------------
Reads a saved email (.eml file) and checks the classic signs of phishing:
sender spoofing, failed authentication (SPF / DKIM / DMARC), links that
hide their real destination, dangerous attachments and pressure language.

Safe by design: it never opens links or runs attachments. It only reads text.

Usage:
    python analyze_email.py suspicious.eml
"""

import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".msi",
                    ".iso", ".img", ".lnk", ".hta", ".zip", ".rar", ".7z",
                    ".docm", ".xlsm", ".html", ".htm")

# Words scammers use to create urgency (Portuguese and English)
PRESSURE_WORDS = (
    "urgente", "imediato", "bloqueado", "bloqueio", "suspens", "irregular",
    "pendência", "pendencia", "multa", "intimação", "intimacao", "último aviso",
    "ultimo aviso", "regularize", "evite", "prazo", "cpf cancelado",
    "urgent", "suspended", "verify your account", "final notice", "immediately",
)

# Organizations commonly impersonated in Brazil, and their real domains
BRANDS = {
    "receita federal": ("gov.br",),
    "sefaz": ("gov.br",),
    "gov.br": ("gov.br",),
    "banco do brasil": ("bb.com.br",),
    "caixa": ("caixa.gov.br",),
    "itaú": ("itau.com.br",), "itau": ("itau.com.br",),
    "bradesco": ("bradesco.com.br",),
    "nubank": ("nubank.com.br",),
    "correios": ("correios.com.br",),
    "microsoft": ("microsoft.com",),
}

SHORTENERS = ("bit.ly", "tinyurl.com", "cutt.ly", "t.co", "encurtador.com.br",
              "is.gd", "rb.gy", "shorturl.at")

POINTS = {"High": 3, "Medium": 2, "Low": 1}


class LinkParser(HTMLParser):
    """Collects (visible text, real destination) for every <a> link."""
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href", ""), ""

    def handle_data(self, data):
        if self._href is not None:
            self._text += data

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._text.strip(), self._href))
            self._href = None


def domain_of(address_or_url):
    value = address_or_url.strip().lower()
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[-1].strip(">")
    host = urlparse(value if "://" in value else "http://" + value).hostname or ""
    return host[4:] if host.startswith("www.") else host


def same_org(d1, d2):
    """True if one domain is the other or a subdomain of it."""
    return bool(d1 and d2) and (d1 == d2 or d1.endswith("." + d2) or d2.endswith("." + d1))


def defang(url):
    """Makes a link unclickable for the report: http -> hxxp, . -> [.]"""
    return url.replace("http", "hxxp").replace(".", "[.]")[:80]


def analyze(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    findings = []  # (risk, check, evidence)
    from_name, from_addr = parseaddr(msg.get("From", ""))
    from_domain = domain_of(from_addr)
    subject = msg.get("Subject", "")

    # 1. Reply-To / Return-Path pointing somewhere else
    for header in ("Reply-To", "Return-Path"):
        _, addr = parseaddr(msg.get(header, ""))
        if addr and not same_org(domain_of(addr), from_domain):
            findings.append(("Medium", f"{header} differs from sender",
                             f"From: {from_domain} / {header}: {domain_of(addr)}"))

    # 2. Display name pretends to be a known organization
    name_and_subject = f"{from_name} {subject}".lower()
    for brand, real_domains in BRANDS.items():
        if brand in name_and_subject and not any(same_org(from_domain, d) for d in real_domains):
            findings.append(("High", "Brand impersonation",
                             f"Mentions '{brand}' but was sent from '{from_domain}'"))
            break

    # 3. Email authentication results (added by the receiving server)
    auth = " ".join(msg.get_all("Authentication-Results", [])).lower()
    auth_summary = "not found"
    if auth:
        results = []
        for check in ("spf", "dkim", "dmarc"):
            m = re.search(check + r"=(\w+)", auth)
            result = m.group(1) if m else "none"
            results.append(check + "=" + result)
            auth_summary = " ".join(results)
            if result != "pass":
                risk = "High" if check == "dmarc" else "Medium"
                findings.append((risk, f"{check.upper()} not passed", f"{check}={result}"))
    else:
        findings.append(("Low", "No authentication results",
                         "Header Authentication-Results not found"))

    # 4. Body: links, pressure words
    html_part = msg.get_body(preferencelist=("html",))
    text_part = msg.get_body(preferencelist=("plain",))
    html = html_part.get_content() if html_part else ""
    text = text_part.get_content() if text_part else re.sub(r"<[^>]+>", " ", html)

    parser = LinkParser()
    parser.feed(html)
    links = parser.links or [("", u) for u in re.findall(r"https?://\S+", text)]

    for visible, href in links:
        real = domain_of(href)
        if re.match(r"\d+\.\d+\.\d+\.\d+$", real):
            findings.append(("High", "Link to a raw IP address", defang(href)))
        elif any(same_org(real, s) for s in SHORTENERS):
            findings.append(("Medium", "Shortened link hides destination", defang(href)))
        shown = re.search(r"[\w-]+(\.[\w-]+)+", visible)
        if shown and "." in shown.group() and not same_org(domain_of(shown.group()), real):
            findings.append(("High", "Link text differs from real destination",
                             f"shows '{shown.group()}' but goes to {defang(href)}"))

    lower = f"{subject} {text}".lower()
    found = sorted({w for w in PRESSURE_WORDS if w in lower})
    if found:
        findings.append(("Medium" if len(found) >= 3 else "Low",
                         "Pressure / urgency language", ", ".join(found[:6])))

    # 4b. Asks for personal data by email
    DATA_REQUESTS = ("cpf", "cnpj", "senha", "telefone", "dados bancários",
                     "número do cartão", "password", "card number")
    asked = sorted({w for w in DATA_REQUESTS if w in lower})
    if asked and any(w in lower for w in ("informando", "retorne", "responda", "envie", "reply")):
        findings.append(("Medium", "Asks for personal data by email", ", ".join(asked)))

    # 5. Attachments
    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        if name.endswith(RISKY_EXTENSIONS) or name.count(".") >= 2:
            findings.append(("High", "Dangerous attachment", name))

    # Which server handed the email to the recipient (last external hop)
    sender_server = "-"
    for r in msg.get_all("Received", []):
        m = re.search(r"from\s+(\S+)\s+\((\S+)\s+\[([\d.]+)\]\)", r)
        if m:
            sender_server = f"{m.group(2).rstrip('.')} [{m.group(3)}]"
            break

    return (msg, from_name, from_domain, subject, len(links), findings,
            auth_summary, sender_server)


def write_report(path, msg, from_name, from_domain, subject, n_links, findings,
                 auth_summary, sender_server):
    score = sum(POINTS[r] for r, _, _ in findings)
    verdict = ("LIKELY PHISHING" if score >= 6 else
               "SUSPICIOUS" if score >= 3 else "NO STRONG SIGNS")
    order = {"High": 0, "Medium": 1, "Low": 2}

    lines = [
        "# Phishing Analysis Report", "",
        f"- **Sender name:** {from_name or '-'}",
        f"- **Sender domain:** {from_domain or '-'}",
        f"- **Subject:** {subject}",
        f"- **Authentication:** {auth_summary}",
        f"- **Sending server:** {sender_server}",
        f"- **Links found:** {n_links}",
        f"- **Risk score:** {score}",
        f"- **Verdict:** **{verdict}**", "",
        "| Risk | Check | Evidence |", "|---|---|---|",
    ]
    for risk, check, ev in sorted(findings, key=lambda f: order[f[0]]):
        lines.append(f"| {risk} | {check} | {ev.replace('|', '/')} |")
    if not findings:
        lines.append("| - | No indicators found | - |")
    lines += ["", "**MITRE ATT&CK:** T1566 Phishing (T1566.001 attachment, T1566.002 link)",
              "**Related controls:** ISO 27001 A.6.3 (awareness training) · A.8.23 (web filtering) · NIST CSF PR.AT-01",
              "", "_Links are defanged (hxxp, [.]) so they cannot be clicked._"]

    report = "\n".join(lines) + "\n"
    with open("phishing_report.md", "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print("Report saved to phishing_report.md")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_email.py suspicious.eml")
        sys.exit(1)
    write_report(sys.argv[1], *analyze(sys.argv[1]))
