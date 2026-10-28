@echo off
cd /d "%~dp0"
title Vesper wallet
echo Starting the Vesper wallet. Your browser opens the wallet page in a moment.
echo Keep this window open while you use it; close it to stop the wallet.
echo.
python wallet_app.py %*
pause
