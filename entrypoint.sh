#!/bin/bash
set -e

export HOME=/home/sulgx

if [ -z "${ADMIN_PASSWORD:-}" ]; then
    echo "ERROR: ADMIN_PASSWORD is not set."
    echo "Set ADMIN_PASSWORD in the platform environment variables and restart."
    exit 1
fi

if [ -z "${SECRET_KEY:-}" ]; then
    echo "ERROR: SECRET_KEY is not set."
    echo "Set SECRET_KEY in the platform environment variables and restart."
    exit 1
fi

mkdir -p /data
chown -R sulgx:sulgx /data

exec gosu sulgx python main.py
