"""
Task 2 - Mini Vulnerability Scanner (educational)
-------------------------------------------------
Checks performed on a target host:
  1. Open TCP ports   - simple connect scan of common ports (+ banner grab)
  2. Weak configs     - risky services exposed (telnet, ftp, smb, rdp, db ports...)
  3. Outdated software - compares banners / HTTP 'Server' header with a small
                         list of minimum safe versions (outdated_versions.json)
  4. Web checks       - missing security headers, HTTP without HTTPS redirect,
                         version disclosure in headers
  5. Report           - prints a summary and writes report.txt + report.json

LEGAL / ETHICAL NOTE
  Scan ONLY systems you own or have written permission to test.
  Default target is 127.0.0.1 (your own machine).
  Use  --demo  to spin up a deliberately weak local test server and scan it.

Usage
  python vuln_scanner.py                      # scans 127.0.0.1
  python vuln_scanner.py -t 192.168.1.10      # your own device / lab
  python vuln_scanner.py --demo               # safe self-contained demo
"""
import argparse
import http.client
import http.server
import json
import os
import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2375: "Docker API", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 27017: "MongoDB",
}

# port -> (severity, explanation)
RISKY = {
    21: ("MEDIUM", "FTP sends credentials in clear text. Use SFTP."),
    23: ("HIGH", "Telnet is unencrypted. Replace with SSH."),
    135: ("MEDIUM", "MS-RPC exposed. Restrict with firewall."),
    139: ("MEDIUM", "NetBIOS exposed. Disable if not needed."),
    445: ("HIGH", "SMB exposed. Block from untrusted networks."),
    1433: ("MEDIUM", "Database port exposed. Bind to localhost / VPN only."),
    1521: ("MEDIUM", "Database port exposed. Bind to localhost / VPN only."),
    2375: ("CRITICAL", "Unauthenticated Docker API gives full host control."),
    3306: ("MEDIUM", "Database port exposed. Bind to localhost / VPN only."),
    3389: ("HIGH", "RDP exposed. Use VPN + MFA, never expose directly."),
    5432: ("MEDIUM", "Database port exposed. Bind to localhost / VPN only."),
    5900: ("HIGH", "VNC exposed. Tunnel through SSH/VPN."),
    6379: ("HIGH", "Redis often has no auth by default. Bind to localhost."),
    27017: ("HIGH", "MongoDB exposed. Enable auth and restrict network."),
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("MEDIUM", "Add HSTS to force HTTPS."),
    "Content-Security-Policy": ("MEDIUM", "Add CSP to reduce XSS risk."),
    "X-Frame-Options": ("LOW", "Add X-Frame-Options to prevent clickjacking."),
    "X-Content-Type-Options": ("LOW", "Add 'nosniff' to stop MIME sniffing."),
    "Referrer-Policy": ("LOW", "Add Referrer-Policy to limit data leakage."),
}


# ---------- scanning ----------
def scan_port(host, port, timeout=0.8):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(0.7)
                if port in (80, 8000, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(200).decode(errors="ignore").strip().replace("\r\n", " | ")
            except OSError:
                pass
            return port, banner
    except OSError:
        return None


def find_open_ports(host, ports):
    with ThreadPoolExecutor(max_workers=50) as ex:
        results = ex.map(lambda p: scan_port(host, p), ports)
    return sorted([r for r in results if r], key=lambda x: x[0])


# ---------- version comparison ----------
def parse_version(text):
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def check_outdated(banner, rules):
    """rules: {"Apache": "2.4.58", ...} -> minimum safe version."""
    found = []
    for product, min_ver in rules.items():
        m = re.search(re.escape(product) + r"[/_ -]?(\d+(?:\.\d+){0,2})", banner, re.I)
        if m and parse_version(m.group(1)) < parse_version(min_ver):
            found.append((product, m.group(1), min_ver))
    return found


# ---------- web checks ----------
def web_checks(host, port, use_tls):
    findings = []
    try:
        if use_tls:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=3, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=3)
        conn.request("GET", "/", headers={"User-Agent": "mini-vuln-scanner/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except Exception as e:
        return [], {}, f"web check failed: {e}"

    for h, (sev, fix) in SECURITY_HEADERS.items():
        if h.lower() == "strict-transport-security" and not use_tls:
            continue
        if h.lower() not in headers:
            findings.append((sev, f"Missing header {h}", fix))
    for h in ("server", "x-powered-by"):
        if h in headers:
            findings.append(("LOW", f"Version disclosure: {h}: {headers[h]}",
                             "Hide product/version details in headers."))
    if not use_tls and resp.status not in (301, 302, 307, 308):
        findings.append(("MEDIUM", f"Port {port} serves plain HTTP without HTTPS redirect",
                         "Redirect HTTP to HTTPS."))
    return findings, headers, None


# ---------- main scan ----------
def run_scan(host, ports):
    with open(os.path.join(HERE, "outdated_versions.json"), encoding="utf-8") as f:
        rules = json.load(f)

    report = {"target": host, "time": datetime.now().isoformat(timespec="seconds"),
              "open_ports": [], "findings": []}

    print(f"[*] Scanning {host} ({len(ports)} ports)...")
    open_ports = find_open_ports(host, ports)
    for port, banner in open_ports:
        name = COMMON_PORTS.get(port, "unknown")
        report["open_ports"].append({"port": port, "service": name, "banner": banner})
        if port in RISKY:
            sev, why = RISKY[port]
            report["findings"].append({"severity": sev, "issue": f"{name} ({port}) is open", "fix": why})
        for product, ver, minimum in check_outdated(banner, rules):
            report["findings"].append({
                "severity": "HIGH",
                "issue": f"Outdated {product} {ver} on port {port}",
                "fix": f"Upgrade to {minimum} or newer."})

    for port, _ in open_ports:
        if port in (80, 8000, 8080, 443, 8443):
            tls = port in (443, 8443)
            items, headers, err = web_checks(host, port, tls)
            for sev, issue, fix in items:
                report["findings"].append({"severity": sev, "issue": f"[port {port}] {issue}", "fix": fix})
            server = headers.get("server", "")
            for product, ver, minimum in check_outdated(server, rules):
                if any(f"Outdated {product} {ver} on port {port}" == f["issue"] for f in report["findings"]):
                    continue  # already reported from the banner
                report["findings"].append({
                    "severity": "HIGH",
                    "issue": f"[port {port}] Outdated {product} {ver} (Server header)",
                    "fix": f"Upgrade to {minimum} or newer."})
    return report


def render(report):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings = sorted(report["findings"], key=lambda f: order[f["severity"]])
    lines = ["=" * 60, "VULNERABILITY SCAN REPORT", "=" * 60,
             f"Target : {report['target']}", f"Time   : {report['time']}", "",
             f"Open ports ({len(report['open_ports'])}):"]
    for p in report["open_ports"]:
        lines.append(f"  - {p['port']:<5} {p['service']:<12} {p['banner'][:60]}")
    lines += ["", f"Findings ({len(findings)}):"]
    if not findings:
        lines.append("  No issues found by these basic checks.")
    for f in findings:
        lines += [f"  [{f['severity']}] {f['issue']}", f"      Fix: {f['fix']}"]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in order}
    lines += ["", "Summary: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
              "Note: basic educational scanner; not a replacement for Nmap/Nessus/OpenVAS."]
    return "\n".join(lines)


# ---------- demo target ----------
class WeakHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.2.15"   # fake old banner on purpose
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"demo weak server")

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, *a):
        pass


def start_demo_server(port=8000):
    srv = http.server.HTTPServer(("127.0.0.1", port), WeakHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    ap = argparse.ArgumentParser(description="Mini vulnerability scanner (educational)")
    ap.add_argument("-t", "--target", default="127.0.0.1", help="host you own / are allowed to scan")
    ap.add_argument("--demo", action="store_true", help="start a weak local demo server and scan it")
    ap.add_argument("--ports", help="comma separated ports (default: common ports)")
    args = ap.parse_args()

    demo = None
    if args.demo:
        demo = start_demo_server()
        args.target = "127.0.0.1"
        print("[demo] Weak test server started on 127.0.0.1:8000")

    if args.target not in ("127.0.0.1", "localhost"):
        ok = input(f"Do you own or have written permission to scan {args.target}? (yes/no): ")
        if ok.strip().lower() != "yes":
            print("Aborted. Scan only systems you are authorised to test.")
            return

    ports = [int(p) for p in args.ports.split(",")] if args.ports else sorted(COMMON_PORTS)
    report = run_scan(args.target, ports)
    text = render(report)
    print("\n" + text)

    with open(os.path.join(HERE, "report.txt"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(HERE, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("\n[+] Saved report.txt and report.json")
    if demo:
        demo.shutdown()


if __name__ == "__main__":
    main()
