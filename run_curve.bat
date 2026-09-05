@echo off
cd /d C:\Users\michael\safety-protocol
C:\Users\michael\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe examples\agent_insurance_sim.py --curve --rogue --png examples\loss_curve.png --events 300 --control-gap 0.12
echo.
echo Chart written to examples\loss_curve.png
pause
