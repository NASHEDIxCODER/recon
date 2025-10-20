#!/usr/bin/env python3

import subprocess
import argparse
import os
import tempfile
from pathlib import Path

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
END_COLOR = "\033[0m"


def display_banner():
    """Displays an aesthetic banner for the tool."""
    yellow = "\033[93m"
    cyan = "\033[96m"
    end_color = "\033[0m"

    banner = f"""
{yellow}
>>=========================================================================<<
||  _  _    _    ___  _  _  ___  ___  ___        ___  ___   ___   ___  ___ ||
|| | \| |  /_\  / __|| || || __||   \|_ _|__ __ / __|/ _ \ |   \ | __|| _ \||
|| | .` | / _ \ \__ \| __ || _| | |) || | \ \ /| (__| (_) || |) || _| |   /||
|| |_|\_|/_/ \_\|___/|_||_||___||___/|___|/_\_\ \___|\___/ |___/ |___||_|_\||
||                                                                         ||
>>=========================================================================<<

{cyan}
          Created by: nashedi_x_coder
{end_color}
    """
    print(banner)


def run_subdomain_discovery(domain, temp_dir):
    """Runs subdomain enumeration tools and returns a set of unique subdomains."""
    print("[*] Stage 1: Discovering subdomains...")
    all_subdomains = set()
    tools = {
        "subfinder": ["subfinder", "-d", domain],
        "assetfinder": ["assetfinder", "--subs-only", domain]
    }
    for tool_name, command in tools.items():
        output_file = os.path.join(temp_dir, f"{tool_name}.txt")
        print(f"    [*] Running {tool_name}...")
        try:
            with open(output_file, 'w') as f:
                subprocess.run(command, stdout=f, check=True, text=True, stderr=subprocess.DEVNULL)
            with open(output_file, 'r') as f:
                all_subdomains.update(line.strip() for line in f)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{RED}[!] Error running {tool_name}. Is it installed and in your PATH?{END_COLOR}")
    print(f"{GREEN}[+] Discovered {len(all_subdomains)} unique subdomains.{END_COLOR}\n")
    return all_subdomains


def find_live_hosts_and_tech(subdomains, temp_dir, output_dir):
    """Takes subdomains, finds live hosts, and detects technologies using httpx."""
    print("[*] Stage 2: Finding live hosts and technologies with httpx...")
    live_hosts_output_file = output_dir / "live_hosts_tech.txt"
    subdomains_file = os.path.join(temp_dir, "all_subdomains.txt")
    with open(subdomains_file, 'w') as f:
        f.write('\n'.join(subdomains))

    httpx_cmd = ["httpx", "-l", subdomains_file, "-o", str(live_hosts_output_file), "-silent", "-tech-detect", "-title",
                 "-status-code"]

    try:
        subprocess.run(httpx_cmd, check=True, text=True, stderr=subprocess.DEVNULL)
        with open(live_hosts_output_file, 'r') as f:
            live_urls = [line.split()[0] for line in f if line.strip()]
        print(f"{GREEN}[+] Found {len(live_urls)} live web servers.{END_COLOR}")
        print(f"[*] Technology report saved to: {live_hosts_output_file}\n")
        return live_urls
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}[!] Error running httpx. Is it installed and in your PATH?{END_COLOR}")
        return []


def take_screenshots(live_hosts, output_dir):
    """Takes a list of live hosts and uses aquatone to take screenshots."""
    print("[*] Stage 3: Taking screenshots with aquatone...")
    if not live_hosts:
        print("[!] No live hosts to screenshot. Skipping.")
        return
    try:
        aquatone_report_path = output_dir / "aquatone_report"
        aquatone_cmd = ["aquatone", "-out", str(aquatone_report_path)]
        process = subprocess.Popen(aquatone_cmd, stdin=subprocess.PIPE, text=True, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        process.communicate(input='\n'.join(live_hosts))
        print(f"{GREEN}[+] Aquatone scan complete.{END_COLOR}\n")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}[!] Error running aquatone. Is it installed and in your PATH?{END_COLOR}")


def run_port_scan(live_hosts, output_dir):
    """Runs an nmap scan on the list of live hosts."""
    print("[*] Optional Stage: Running Nmap port scan...")
    if not live_hosts: return

    hosts_to_scan = {url.split('//')[1].split('/')[0].split(':')[0] for url in live_hosts}

    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as f:
        f.write('\n'.join(hosts_to_scan))
        input_file = f.name

    output_file = output_dir / "nmap_scan.txt"
    nmap_cmd = ["nmap", "-iL", input_file, "-oN", str(output_file)]

    try:
        subprocess.run(nmap_cmd, check=True, text=True, stderr=subprocess.DEVNULL)
        print(f"{GREEN}[+] Nmap scan complete. Results saved to: {output_file}{END_COLOR}\n")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}[!] Error running nmap. Is it installed and in your PATH?{END_COLOR}")
    finally:
        os.remove(input_file)


def run_vulnerability_scan(live_hosts, output_dir):
    """Runs a nuclei scan on the list of live hosts."""
    print("[*] Optional Stage: Running Nuclei vulnerability scan...")
    if not live_hosts: return

    output_file = output_dir / "nuclei_scan.txt"
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as f:
        f.write('\n'.join(live_hosts))
        input_file = f.name

    nuclei_cmd = ["nuclei", "-l", input_file, "-o", str(output_file)]

    try:
        subprocess.run(nuclei_cmd, check=True, text=True, stderr=subprocess.DEVNULL)
        print(f"{GREEN}[+] Nuclei scan complete. Results saved to: {output_file}{END_COLOR}\n")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}[!] Error running nuclei. Is it installed and in your PATH?{END_COLOR}")
    finally:
        os.remove(input_file)


def main():
    display_banner()
    parser = argparse.ArgumentParser(description="An advanced recon suite by nashedi_x_coder.")
    parser.add_argument("-d", "--domain", required=True, help="The target domain (e.g., example.com).")
    parser.add_argument("-o", "--output",
                        help="Directory to save all output files (default: a directory named after the domain).")
    parser.add_argument("--port-scan", action="store_true", help="Run an Nmap port scan on live hosts.")
    parser.add_argument("--vuln-scan", action="store_true", help="Run a Nuclei vulnerability scan on live hosts.")
    args = parser.parse_args()


    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = Path(args.domain)


    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_dir:
        subdomains = run_subdomain_discovery(args.domain, temp_dir)
        live_hosts = find_live_hosts_and_tech(subdomains, temp_dir, output_dir)

        if live_hosts:
            take_screenshots(live_hosts, output_dir)
            if args.port_scan:
                run_port_scan(live_hosts, output_dir)

            if args.vuln_scan:
                run_vulnerability_scan(live_hosts, output_dir)

    print(f"[*] Workflow finished. All reports are saved in the '{output_dir}' directory.")


if __name__ == "__main__":
    main()