@echo off
cd /d "%~dp0"
title Vesper self-test
python selftest.py
echo.
pause
