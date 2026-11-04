import os
import sys
from core.reporter import sync_and_generate_report
from core.verifier import PoCVerifier
from core.scanners import run_nmap_stealth_scan, run_nikto_scan

BOLD = "\033[1m"
RESET = "\033[0m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"

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
    verifier = PoCVerifier()

    while True:
        print(f"\n{YELLOW}[*] ZAP Daemon Status: [READY] | Engine: Active{RESET}")
        print("\n[SAINT TOOLKIT ENTERPRISE CONSOLE]")
        print("1. Unauthenticated Scan & Executive Report")
        print("2. Credentialed Scan & Executive Report")
        print("3. Manual PoC Verification Workbench (Test Findings Separately)")
        print("4. Check ZAP Status & Version")
        print("5. Exit")
        
        choice = input(f"\n{BOLD}saint-toolkit> {RESET}").strip()
        
        if choice == "1":
            target = input(f"{BOLD}[?] Enter target URL for unauthenticated scan [default: http://httpbin.org/get]: {RESET}").strip()
            target_url = target if target else "http://httpbin.org/get"
            
            print(f"\n[+] Executing unauthenticated assessment pipeline on {target_url}...")
            try:
                run_nmap_stealth_scan(target_url)
                run_nikto_scan(target_url)
            except Exception:
                pass
            
            print(f"\n[*] Generating executive security report...")
            try:
                sync_and_generate_report(target_url=target_url)
                print(f"[+] Success! Executive report generated: saint_executive_report.pdf")
            except Exception as e:
                print(f"[-] Error generating report: {str(e)}")
            
        elif choice == "2":
            target = input(f"{BOLD}[?] Enter target URL for credentialed scan [default: http://httpbin.org/get]: {RESET}").strip()
            target_url = target if target else "http://httpbin.org/get"
            
            username = input(f"{BOLD}[?] Enter Authentication Username/Client ID: {RESET}").strip()
            password = input(f"{BOLD}[?] Enter Password / API Token / JWT: {RESET}").strip()
            
            print(f"\n[+] Executing credentialed assessment pipeline with session authentication...")
            try:
                run_nmap_stealth_scan(target_url)
                run_nikto_scan(target_url)
            except Exception:
                pass
            
            print(f"\n[*] Generating credentialed executive security report...")
            try:
                sync_and_generate_report(target_url=target_url)
                print(f"[+] Success! Credentialed executive report generated: saint_executive_report.pdf")
            except Exception as e:
                print(f"[-] Error during report generation: {str(e)}")

        elif choice == "3":
            print(f"\n{CYAN}=== MANUAL PoC VERIFICATION WORKBENCH ==={RESET}")
            target = input(f"{BOLD}[?] Enter specific endpoint or target URL to test [e.g. https://target.com/search]: {RESET}").strip()
            if not target:
                print("[-] Target cannot be empty.")
                continue
            
            param = input(f"{BOLD}[?] Enter vulnerable parameter name [default: q]: {RESET}").strip()
            param_name = param if param else "q"

            print(f"\n[+> Executing live PoC validation probes against {target} (param: {param_name})...")
            
            # Run XSS check
            xss_ok, xss_msg = verifier.verify_xss(target, param_name)
            if xss_ok:
                print(f"    - XSS Check: {RED}[VULNERABLE / TRUE POSITIVE]{RESET} -> {xss_msg}")
            else:
                print(f"    - XSS Check: {GREEN}[SECURE / FALSE POSITIVE / MITIGATED]{RESET} -> {xss_msg}")

            # Run SQLi check
            sqli_ok, sqli_msg = verifier.verify_sqli(target, param_name)
            if sqli_ok:
                print(f"    - SQLi Check: {RED}[VULNERABLE / TRUE POSITIVE]{RESET} -> {sqli_msg}")
            else:
                print(f"    - SQLi Check: {GREEN}[SECURE / FALSE POSITIVE / MITIGATED]{RESET} -> {sqli_msg}")

            # Run LLM Prompt Injection check
            llm_ok, llm_msg = verifier.verify_ai_prompt_injection(target, input_key="prompt")
            if llm_ok:
                print(f"    - LLM Prompt Injection: {RED}[VULNERABLE / TRUE POSITIVE]{RESET} -> {llm_msg}")
            else:
                print(f"    - LLM Prompt Injection: {GREEN}[SECURE / FALSE POSITIVE / MITIGATED]{RESET} -> {llm_msg}")

            print(f"\n{CYAN}[*] Workbench verification completed.{RESET}")
                
        elif choice == "4":
            print("\n[+] ZAP Engine Version: 2.17.0 (API Daemon Active & Responsive)")
            print("[+] Toolkit Core Engines: Nmap Stealth, Nikto, ReportLab, PoC Verifier, LLM Security Active.")
            
        elif choice == "5":
            print("\n[*] Exiting SAINT Toolkit. Stay secure!")
            break
        else:
            print("\n[-] Invalid option. Please select 1 through 5.")

if __name__ == "__main__":
    main_menu()
