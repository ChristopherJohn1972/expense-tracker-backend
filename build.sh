#!/bin/bash
# Upgrade pip and install dependencies
pip install --upgrade pip setuptools wheel

# Install PyAudio using a pre-built wheel (no system dependencies needed)
pip install PyAudio --global-option='--global-option=-I/usr/include/x86_64-linux-gnu/'

# Install other requirements
pip install -r requirements.txt
