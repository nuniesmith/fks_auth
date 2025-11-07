# scripts/docker/watch.sh - File watcher script
#!/bin/bash

WATCH_PATHS=${WATCH_PATHS:-"/watch/src"}
BUILD_COMMAND=${BUILD_COMMAND:-"echo 'Build command not set'"}
LOG_LEVEL=${LOG_LEVEL:-"INFO"}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$LOG_LEVEL] $1"
}

log "Starting file watcher..."
log "Watching paths: $WATCH_PATHS"
log "Build command: $BUILD_COMMAND"

# Initial build
log "Running initial build..."
eval "$BUILD_COMMAND"

# Watch for changes
inotifywait -m -r -e modify,create,delete,move $WATCH_PATHS --format '%w%f %e' |
while read FILE EVENT; do
    if [[ "$FILE" == *.cs ]]; then
        log "Detected change in $FILE ($EVENT)"
        log "Triggering build..."
        eval "$BUILD_COMMAND"
    fi
done