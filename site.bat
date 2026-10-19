@echo off
cd /d "%~dp0"
title Vesper website (http://127.0.0.1:8885)
start http://127.0.0.1:8885
python -m http.server 8885 --directory site
pause
