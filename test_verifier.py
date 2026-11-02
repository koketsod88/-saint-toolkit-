from core.verifier import PoCVerifier

def run_tests():
    print("[*] Initializing SAINT PoC Verifier Test Suite...")
    verifier = PoCVerifier(timeout=5)

    # Using httpbin.org as a live target to test connection and response handling
    target_url = "http://httpbin.org/get"
    param = "q"

    print(f"\n[1] Testing XSS Verification on {target_url} (param: {param})...")
    is_valid, reason = verifier.verify_xss(target_url, param)
    print(f"    Result: {'VULNERABLE (True Positive)' if is_valid else 'SAFE / FALSE POSITIVE'}")
    print(f"    Details: {reason}")

    print(f"\n[2] Testing SQLi Verification on {target_url} (param: {param})...")
    is_valid, reason = verifier.verify_sqli(target_url, param)
    print(f"    Result: {'VULNERABLE (True Positive)' if is_valid else 'SAFE / FALSE POSITIVE'}")
    print(f"    Details: {reason}")

    print("\n[*] Test suite execution completed.")

if __name__ == "__main__":
    run_tests()
