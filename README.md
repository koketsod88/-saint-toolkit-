# SAINT Security Toolkit

**SAINT-Toolkit** is an enterprise-grade, deterministic Vulnerability Assessment and Penetration Testing (VAPT) pipeline.

## Installation & Setup Guide

### Option 1: Native Installation on Kali Linux

1. **Clone the Repository**
   ```bash
   git clone [https://github.com/koketsod88/-saint-toolkit-.git](https://github.com/koketsod88/-saint-toolkit-.git)
   cd -saint-toolkit-
   ```

2. **Install System Dependencies**
   ```bash
   sudo apt update && sudo apt install -y python3 python3-pip nmap nikto
   ```

3. **Install Python Dependencies**
   ```bash
   pip install requests reportlab beautifulsoup4
   ```

4. **Launch the Toolkit Console**
   ```bash
   python3 ui.py
   ```

---

## Option 2: Docker Containerized Deployment

1. **Build the Docker Image**
   ```bash
   docker build -t saint-toolkit-scanner .
   ```

2. **Run the Container Interactive Console**
   ```bash
   docker run --rm -it -v "$(pwd):/app" saint-toolkit-scanner
   ```
