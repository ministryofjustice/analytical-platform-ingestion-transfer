#!/usr/bin/env bash

set -euo pipefail

sudo apt-get update

# Install agent package manager dependencies.
apm install --frozen

# Upgrade Pip
pip install --upgrade pip

# Install dependencies
pip install --requirement requirements-dev.txt
