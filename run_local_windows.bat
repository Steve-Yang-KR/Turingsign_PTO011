@echo off
if "%PTO_SETUP_TOKEN%"=="" set PTO_SETUP_TOKEN=local-alpha-setup-change-me
set PYTHONPATH=%CD%
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
