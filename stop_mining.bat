@echo off
cd /d "%~dp0"
title Vesper - stop mining
python coin.py mine stop
echo.
pause
