@echo off
cd /d "%~dp0"
title Vesper node 2 (port 8881)
echo Second node for the peer-to-peer demo. It downloads the chain from node 1
echo and follows it. Explorer: http://127.0.0.1:8881
echo To make it compete for blocks too, add:  --mine --mine-to YOUR_ADDRESS
echo.
python node.py --port 8881 --data-dir data2 --peer http://127.0.0.1:8880
pause
