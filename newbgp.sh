#!/bin/bash

# 获取用户输入
read -p "请输入对方的dn42ip: " dn42ip
read -p "请输入对方的ASN: " asn
read -p "请输入BGP会话名字: " bgp_name

# 构建配置文件路径
config_file="/etc/bird/peers/${bgp_name}.conf"

# 构建配置文件内容
config="
protocol bgp ${bgp_name} from dnpeers {
    neighbor ${dn42ip} as ${asn};
    ipv4 {
        next hop self;
        extended next hop on;
    };
}
"

# 写入配置文件
echo "${config}" | sudo tee "${config_file}" > /dev/null

# 执行命令
sudo birdc configure
sudo birdc show protocol
