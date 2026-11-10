import requests
import json
from urllib.parse import urljoin

class AdvancedAssetDiscovery:
    def __init__(self, target_url, timeout=5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.discovered_assets = []

    def run_full_recon(self):
        print("[*] Running advanced deterministic asset & threat discovery...")
        self.check_sensitive_paths()
        self.check_cloud_metadata_patterns()
        self.check_api_endpoints()
        return self.discovered_assets

    def check_sensitive_paths(self):
        sensitive_files = [
            ".env", ".git/config", ".gitlab-ci.yml", "swagger.json", 
            "openapi.json", "graphql", "api/v1/docs", "backup.zip", "db.sql"
        ]
        for path in sensitive_files:
            url = urljoin(self.target_url + "/", path)
            try:
                resp = requests.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    self.discovered_assets.append({
                        "type": "Exposed Sensitive Asset",
                        "path": path,
                        "url": url,
                        "status": resp.status_code,
                        "severity": "High" if ".env" in path or ".git" in path else "Medium"
                    })
            except requests.RequestException:
                continue

    def check_cloud_metadata_patterns(self):
        metadata_paths = [
            "latest/meta-data/",
            "computeMetadata/v1/"
        ]
        for path in metadata_paths:
            url = f"http://169.254.169.254/{path}"
            try:
                resp = requests.get(url, timeout=2, headers={"Metadata": "true"})
                if resp.status_code == 200:
                    self.discovered_assets.append({
                        "type": "Cloud Metadata Exposure",
                        "path": path,
                        "url": url,
                        "severity": "Critical"
                    })
            except requests.RequestException:
                pass

    def check_api_endpoints(self):
        endpoints = ["/graphql", "/swagger/v1/swagger.json", "/api/swagger.json"]
        for ep in endpoints:
            url = urljoin(self.target_url + "/", ep)
            try:
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200 and ("swagger" in resp.text.lower() or "data" in resp.text.lower() or "query" in resp.text.lower()):
                    self.discovered_assets.append({
                        "type": "API / Documentation Endpoint",
                        "path": ep,
                        "url": url,
                        "severity": "Low"
                    })
            except requests.RequestException:
                continue

def discover_hidden_assets(target_url):
    scanner = AdvancedAssetDiscovery(target_url)
    return scanner.run_full_recon()
