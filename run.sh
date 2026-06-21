#!/bin/bash
# Network Protocol Analyzer - 启动脚本
# 自动激活 conda 环境并启动 GUI

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONDA_ENV="net_design"

# 获取 conda 环境中的 python 路径
CONDA_BASE="$(conda info --base 2>/dev/null)"
if [ -z "$CONDA_BASE" ]; then
    echo "Error: conda not found. Please install conda first."
    exit 1
fi

PYTHON="$CONDA_BASE/envs/$CONDA_ENV/bin/python3"

if [ ! -f "$PYTHON" ]; then
    echo "Error: conda environment '$CONDA_ENV' not found."
    echo "Run: conda env create -f environment.yml"
    exit 1
fi

# Wayland 用户需要设置 DISPLAY
if [ -z "$DISPLAY" ]; then
    export DISPLAY=:1
    echo "Set DISPLAY=:1 for Wayland"
fi

cd "$SCRIPT_DIR"
exec "$PYTHON" -m src "$@"
