#!/bin/bash
set -e

# InfraScan Entrypoint Script
# Handles switching between Web App and CLI modes

# 1. Explicitly check for 'web' mode
if [ "$1" = "web" ]; then
    shift
    echo "Starting InfraScan Web Server..."
    if [ $# -eq 0 ]; then
        exec gunicorn --bind 0.0.0.0:5000 --timeout 600 --workers 2 app:app
    else
        exec gunicorn "$@"
    fi
fi

# 2. Check for 'cli' mode (legacy compatibility or explicit choice)
if [ "$1" = "cli" ]; then
    shift
    exec python /opt/infrascan/cli.py "$@"
fi

# 3. Check if the command is an existing system command (like bash, sh, ls)
if command -v "$1" >/dev/null 2>&1; then
    exec "$@"
fi

# 4. Default: Run as a CLI tool
# This handles cases like 'docker run ... --scanner ...' or just 'docker run ...'
# if CMD is set to something other than 'web' or 'cli' or a system command.
echo "Running InfraScan CLI..."
exec python /opt/infrascan/cli.py "$@"
