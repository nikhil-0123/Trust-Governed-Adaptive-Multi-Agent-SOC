#!/bin/bash
# TGAM-SOC — Run Attack Simulation from Ubuntu WSL
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/wsl_attack_simulation.py"

echo "=========================================================="
echo " Starting TGAM-SOC Multi-Stage Attack Simulation via WSL "
echo "=========================================================="

python3 "$PYTHON_SCRIPT"
