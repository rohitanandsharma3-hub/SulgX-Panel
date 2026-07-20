#!/bin/bash
set -e
export HOME=/home/sulgx
mkdir -p /data 2>/dev/null || true
chown -R sulgx:sulgx /data 2>/dev/null || true
exec gosu sulgx python main.py
