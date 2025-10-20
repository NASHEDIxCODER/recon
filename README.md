# Advanced Recon Suite

![Made with Python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)

An all-in-one reconnaissance suite for bug bounty hunters and penetration testers. This tool automates the workflow of subdomain discovery, live host identification, technology detection, port scanning, screenshotting, and vulnerability scanning.

### Created by: nashedi_x_coder

***

---
## 📜 Description

This suite orchestrates a chain of popular open-source tools to perform a comprehensive reconnaissance scan on a target domain. It's designed to be modular and efficient, saving all results into a well-organized output directory. The goal is to automate the initial, time-consuming phase of a penetration test or bug bounty hunt.

## ✨ Features

-   **Subdomain Discovery:** Aggregates results from `subfinder` and `assetfinder`.
-   **Live Host & Tech Detection:** Uses `httpx` to find live web servers and identify the technologies they run.
-   **Visual Recon:** Takes screenshots of all live websites using `aquatone` for quick visual analysis.
-   **Port Scanning (Optional):** Runs an `nmap` scan on discovered hosts to find open ports.
-   **Vulnerability Scanning (Optional):** Runs `nuclei` with its default templates to find known vulnerabilities.
-   **Modular & Flexible:** Use optional flags to choose the depth of your scan.
-   **Organized Output:** Saves all reports into a single, clean directory, which can be specified with the `--output` flag.

## ⚙️ Workflow

The tool follows a logical chain of recon activities:

`Domain -> Subdomain Discovery -> Live Host Detection -> Screenshots & Optional Scans`



## 🚀 Getting Started

### Prerequisites

This script is an orchestrator and requires several external tools to be installed on your system.

-   `git`
-   `python3` and `python3-pip`
-   `go` (for installing some tools)
-   `subfinder`
-   `assetfinder`
-   `httpx`
-   `nmap`
-   `nuclei`
-   `aquatone`

### Installation

#### **On Arch Linux / BlackArch:**

```bash
# Install system dependencies
sudo pacman -Syu
sudo pacman -S git python-pip go subfinder assetfinder httpx nmap nuclei

# Install aquatone using Go
go install [github.com/michenriksen/aquatone@latest](https://github.com/michenriksen/aquatone@latest)

# Install system dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-pip golang-go subfinder assetfinder httpx nmap nuclei

# Install aquatone using Go
go install [github.com/michenriksen/aquatone@latest](https://github.com/michenriksen/aquatone@latest)

Final Setup Steps:
Clone the repository:

Bash

git clone [https://github.com/NASHEDIxCODER/recon.git](https://github.com/NASHEDIxCODER/recon.git)
cd recon
Install Python libraries:

Bash

pip install -r requirements.txt
(Recommended) Make it a Global Command: Move the script to a directory in your PATH to run it from anywhere.

Bash

sudo mv recon.py /usr/local/bin/recon
sudo chmod +x /usr/local/bin/recon
💻 Usage
Once set up as a global command, you can run recon from any directory.

Basic Scan (Subdomains, Live Hosts, Screenshots):

Bash

recon -d example.com
Full Scan (with Ports and Vulnerabilities):

Bash

recon -d example.com --port-scan --vuln-scan
Full Scan with a Custom Output Directory:

Bash

recon -d example.com -o /path/to/results/example --port-scan --vuln-scan
🤝 Contributing
Contributions are welcome and greatly appreciated! This project is open source, and the community is encouraged to help make it even better.

You can contribute in several ways:

Reporting Bugs: If you find a bug, please open an issue on the GitHub repository.

Suggesting Enhancements: Have an idea to make this tool better? Feel free to open an issue to discuss it.

Pull Requests: If you want to add a new feature or fix a bug yourself, please follow the standard fork and pull request workflow.

📄 License
This project is licensed under the MIT License.