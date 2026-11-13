@echo off
echo VLAN Segmentation Audit Toolkit v1.0.0
echo.
echo Note: Administrator privileges recommended for full functionality
echo.
python -m pip install -r requirements.txt --quiet 2>nul
python vlan_audit.py %*
pause
