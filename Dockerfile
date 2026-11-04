FROM kalilinux/kali-rolling

# Install system security tools and Perl dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    nmap \
    nikto \
    libxml-writer-perl \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy toolkit code
COPY . /app

ENV PYTHONPATH=/app

ENTRYPOINT ["python3", "ui.py"]
