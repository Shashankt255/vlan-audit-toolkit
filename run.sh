#!/bin/bash
echo "VLAN Segmentation Audit Toolkit v1.0.0"
echo "Note: Root privileges required for ICMP, ARP, and VLAN checks"
echo ""
pip3 install -r requirements.txt -q 2>/dev/null
if [ "$EUID" -ne 0 ]; then
    echo "[!] Running without root - some checks will be skipped"
    echo "[!] Run with: sudo ./run.sh $@"
    echo ""
fi
python3 vlan_audit.py "$@"
