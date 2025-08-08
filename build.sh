#!/bin/bash
# Upgrade pip, setuptools, and wheel
pip install --upgrade pip setuptools wheel

# Install PortAudio (required for PyAudio)
apt-get update && apt-get install -y portaudio19-dev

# Install Python dependencies
pip install -r requirements.txt