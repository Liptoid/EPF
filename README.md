# PSL - CVE & Exploit Intelligence Tool

> Search for CVEs in the NVD database and find related exploits in Exploit-DB  
> Built with Python, Rich & Requests

---

## 🚀 Overview

PSL CVE & Exploit Tool allows you to:

- Search for CVEs by service, product, version, or CVE ID
- Retrieve CVSS score and risk classification
- Generate links to Exploit-DB for known exploits
- Display results in a clean CLI table

This tool is designed for **educational and authorized security research purposes only**.

---

## ⚙️ Features

✔ CVE Lookup from NVD  
✔ CVSS Score Calculation  
✔ Risk Classification (Low / Medium / High / Critical)  
✔ Exploit-DB Links for each CVE  
✔ Rich CLI Table Display  
✔ Quick search by product/service or CVE ID  
✔ JSON Export (optional to implement)  

---

## 🛠 Requirements

- Python 3.10+
- Packages: `requests`, `rich`

### Install Dependencies

```bash
pip install requests rich
