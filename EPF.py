import requests
import argparse
from rich.console import Console
from rich.table import Table

console = Console()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ==========================
# Risk Classification
# ==========================
def classify_risk(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"

# ==========================
# Search Exploit-DB
# ==========================
def search_exploitdb(cve_id):
    url = f"https://www.exploit-db.com/search?cve={cve_id}"
    return url  # returning search link only

# ==========================
# Search NVD
# ==========================
def search_nvd(query):
    params = {
        "keywordSearch": query,
        "resultsPerPage": 5
    }

    response = requests.get(NVD_API, params=params, timeout=15)
    data = response.json()

    if "vulnerabilities" not in data:
        console.print("[red]No results found.[/red]")
        return

    table = Table(title=f"CVE + Exploit Results for: {query}")

    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Exploit-DB")
    table.add_column("Description")

    for item in data["vulnerabilities"]:
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"][:100] + "..."

        metrics = cve.get("metrics", {})
        cvss_score = 0

        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        severity = classify_risk(float(cvss_score)) if cvss_score else "N/A"

        exploit_link = search_exploitdb(cve_id)

        table.add_row(
            cve_id,
            str(cvss_score),
            severity,
            exploit_link,
            description
        )

    console.print(table)

# ==========================
# Main
# ==========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE + Exploit-DB Lookup Tool")
    parser.add_argument("query", help="Service name, version, or CVE ID")

    args = parser.parse_args()

    console.print("\n[bold yellow]Searching NVD & Exploit-DB...[/bold yellow]\n")
    search_nvd(args.query)
