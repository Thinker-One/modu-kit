#!/bin/bash

CPU_CORES=$(nproc)

# 清空
if [ "$1" == "distclean" ]; then
    echo "清理构建目录..."
    rm -rf build
    exit 0
fi

# 配置
if [ $# -eq 1 ] && [ "$1" == debug ]; then
    echo "启用 Debug 模式"
    BUILD_TYPE="Debug"
else
    echo "启用 Release 模式"
    BUILD_TYPE="Release"
fi

cmake -B build -DCMAKE_BUILD_TYPE=$BUILD_TYPE
cmake --build build -j$CPU_CORES