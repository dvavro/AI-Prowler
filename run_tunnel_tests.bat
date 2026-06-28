@echo off
cd /d "C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
C:\Users\david\AppData\Local\Programs\Python\Python311\python.exe -m pytest tests/test_tunnel_ingress_e2e.py -v -m "not e2e" --tb=short
