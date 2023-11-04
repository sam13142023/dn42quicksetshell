#!/bin/bash

# 检查 curl 是否已安装
if ! command -v curl &> /dev/null; then
    echo "curl 未安装，正在安装..."
    sudo apt-get install curl
fi

# 检查文件是否存在，如果不存在则使用 curl 下载
if [ ! -f "newwg.sh" ]; then
    echo "依赖1不存在，正在下载..."
    curl -O https://sam1314.com/dn42/newwg.sh
fi

if [ ! -f "newbgp.sh" ]; then
    echo "依赖2不存在，正在下载..."
    curl -O https://sam1314.com/dn42/newbgp.sh
fi


# 为脚本文件添加执行权限
chmod +x newwg.sh newbgp.sh

# 执行1.sh
./newwg.sh

# 执行2.sh
./newbgp.sh
