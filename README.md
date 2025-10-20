# Advanced Recon Suite

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

An all-in-one reconnaissance suite 🐍 written in Python to automate the bug bounty workflow, from subdomain discovery to vulnerability scanning. Orchestrates `subfinder`,`assetfinder`, `httpx`, `nmap`, `nuclei`,.

</div>


### Created by: nashedi_x_coder

***
---
## 📜 Description

This suite orchestrates a chain of popular open-source tools to perform a comprehensive reconnaissance scan on a target domain. It's designed to be modular and efficient, saving all results into a well-organized output directory. The goal is to automate the initial, time-consuming phase of a penetration test or bug bounty hunt.

---
## ✨ Features

-   **Subdomain Discovery:** Aggregates results from `subfinder` and `assetfinder`.
-   **Live Host & Tech Detection:** Uses `httpx` to find live web servers and identify the technologies they run.
-   **Visual Recon:** Takes screenshots of all live websites using `aquatone` for quick visual analysis.
-   **Port Scanning (Optional):** Runs an `nmap` scan on discovered hosts to find open ports.
-   **Vulnerability Scanning (Optional):** Runs `nuclei` with its default templates to find known vulnerabilities.
-   **Modular & Flexible:** Use optional flags to choose the depth of your scan.
-   **Organized Output:** Saves all reports into a single, clean directory, which can be specified with the `--output` flag.
---
## ⚙️ Workflow

The tool follows a logical chain of recon activities:

`Domain -> Subdomain Discovery -> Live Host Detection -> Screenshots & Optional Scans`

---
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

#### On Arch Linux / BlackArch:

# Install system dependencies
```bash
sudo pacman -Syu
sudo pacman -S git python-pip go subfinder assetfinder httpx nmap nuclei
```

# Install aquatone using Go
```bash
go install github.com/michenriksen/aquatone@latest
```

#### On Debian / Ubuntu / Kali Linux:
# Install system dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-pip golang-go subfinder assetfinder httpx nmap nuclei
```

# Install aquatone using Go
```bash
go install [github.com/michenriksen/aquatone@latest](https://github.com/michenriksen/aquatone@latest)
```


#### Install system dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-pip golang-go subfinder assetfinder httpx nmap nuclei
```

# Install aquatone using Go
```bash
go install github.com/michenriksen/aquatone@latest
````

### Final Setup Steps:

**Clone the repository:**

    ```bash

    git clone https://github.com/NASHEDIxCODER/recon.git
    cd recon
    ```

**(Recommended) Make it a Global Command:**
    Move the script to a directory in your PATH to run it from anywhere.

    ```bash

    sudo mv recon.py /usr/local/bin/recon
    sudo chmod +x /usr/local/bin/recon

    ```

---
## 💻 Usage

Once set up as a global command, you can run `recon` from any directory.

**Basic Scan (Subdomains, Live Hosts, Screenshots):**
```bash
recon -d example.com

recon -d example.com --port-scan --vuln-scan

recon -d example.com -o /path/to/results/example --port-scan --vuln-scan
````

markdown
---
## 🤝 Contributing

Contributions are welcome and greatly appreciated! This project is open source, and the community is encouraged to help make it even better.

You can contribute in several ways:
-   **Suggesting Enhancements:** Have an idea to make this tool better? Feel free to open an issue to discuss it.
-   **Pull Requests:** If you want to add a new feature or fix a bug yourself, please follow the standard fork and pull request workflow.

---
## 📄 License

This project is licensed under the MIT License.