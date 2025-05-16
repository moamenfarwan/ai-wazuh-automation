#!/bin/bash

WATCH_DIR="/root/ML-Based-Malware-Detection"
LOG_FILE="/var/log/ai_malware_detection.log"
VENV_PATH="/root/venv"

# Activate virtual environment
source "$VENV_PATH/bin/activate"

inotifywait -m -e create --format "%f" "$WATCH_DIR" | while read NEW_FILE
do
    FILEPATH="$WATCH_DIR/$NEW_FILE"
    echo "New file detected: $FILEPATH"

    # Run the prediction
    python3 /root/ML-Based-Malware-Detection/predict_file.py "$FILEPATH"
done

