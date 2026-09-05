@echo off
cd /d C:\Users\michael\safety-protocol
C:\Users\michael\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe examples\agent_insurance_sim.py --runs 1000 --events 200 --seed 42
echo.
echo Done.
pause
