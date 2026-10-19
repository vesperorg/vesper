@echo off
cd /d "%~dp0"
title Vesper wallet
python coin.py wallet show
echo.
pause
