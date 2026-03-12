#!/bin/bash
set -e

# InfraScan Entrypoint Script
# Handles switching between Web App and CLI modes

# If the first argument is "cli" (legacy compatibility)
if [ "$1" = "cli" ]; then
    shift
    exec python /app/cli.py "$@"
fi

# If the first argument looks like a CLI flag (starts with -)
if [[ $1 == -* ]]; then
    exec python /app/cli.py "$@"
fi

# Default behavior: run as a web server
# This allows 'docker run ...' to start the web app
# and 'docker run ... cli ...' or 'docker run ... --scanner ...' to run the CLI
if [ "$1" = "web" ]; then
    shift
fi

echo "Starting InfraScan Web Server..."
# Run gunicorn with provided arguments or defaults
if [ $# -eq 0 ]; then
    exec gunicorn --bind 0.0.0.0:5000 --timeout 600 --workers 2 app:app
else
    exec gunicorn "$@"
fi
