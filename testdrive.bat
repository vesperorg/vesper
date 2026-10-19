@echo off
cd /d "%~dp0"
title Vesper test drive
echo The whole test drive on two throwaway nodes: about 5 minutes. Nothing of yours is touched.
echo.
python testdrive.py
echo.
pause
