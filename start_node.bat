@echo off
cd /d "%~dp0"
title Vesper node (port 8880)
echo Starting the Vesper node. Explorer: http://127.0.0.1:8880
echo Mining starts automatically if a wallet exists (run wallet.bat first).
echo.
python node.py --mine
pause
