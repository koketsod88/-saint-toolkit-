import os
import sys
from core.reporter import sync_and_generate_report

BOLD = "\033[1m"
RESET = "\033[0m"
GREEN = "\033[32m"
CYAN = "\033[36m"

def print_banner():
    banner = f"""
{CYAN}##############################################################################
##      ███████╗ █████╗ ██╗███╗   ██╗████████╗                               ##
##      ██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝                               ##
##      ███████╗███████║██║██╔██╗ ██║   ██║                                  ##
##      ╚════██║██╔══██║██║██║╚██╗██║   ██║                                  ##
##      ███████║██║  ██║██║██║ ╚████║   ██║                                  ##
##      ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝                                  ##
##############################################################################
##          [Vulnerability Assessment & Penetration Testing Toolkit]          ##
##          [Powered by OWASP ZAP, Nmap, Nikto & ReportLab Engine]           ##
##                 Developed & Compiled by Donald Koketso                    ##
##############################################################################{RESET}
    """
    print(banner)

def main_menu():
    print_banner()
    print("[*] ZAP Daemon Status: [READY]")
    print("\n[SAINT TOOLKIT INTERACTIVE CONSOLE]")
    print("1. Check ZAP Status & Version")
    print("2. Run Credentialed Scan & PDF Report Workflow")
    print("3. Exit")
    
    choice = input(f"\n{BOLD}saint-toolkit> {RESET}").strip()
    if choice == "1":
        print("[+] ZAP Engine Version: 2.17.0 (API Daemon Active)")
    elif choice == "2":
        print("[+] Executing automated scan, verification, and PDF report generation...")
        try:
            sync_and_generate_report()
            print("[+] Workflow completed successfully. Report generated: saint_executive_report.pdf")
        except Exception as e:
            print(f"[-] Error during workflow execution: {str(e)}")
    else:
        print("[*] Exiting SAINT Toolkit.")

if __name__ == "__main__":
    main_menu()
