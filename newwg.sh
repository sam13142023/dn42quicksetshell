#!/bin/bash

echo "请输入隧道名："
read -r filename

echo "请输入你的私钥："
read -r private_key

echo "请输入你监听的端口："
read -r listen_port

echo "请输入你的dn42 IP："
read -r your_dn42_ip

echo "请输入对方的dn42 IP："
read -r peer_dn42_ip

echo "请输入对方的公钥："
read -r peer_public_key

echo "请输入对方的endpoint："
read -r peer_endpoint

content="[Interface]
PrivateKey = $private_key
ListenPort = $listen_port
PostUp = ip addr add $your_dn42_ip peer $peer_dn42_ip dev %i
Table = off

[Peer]
PublicKey = $peer_public_key
Endpoint = $peer_endpoint
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64"

echo "$content" | sudo tee "/etc/wireguard/$filename.conf" > /dev/null

echo "内容已写入到 /etc/wireguard/$filename.conf 文件中。"

sudo systemctl enable "wg-quick@$filename"
wg-quick up $filename
echo "隧道 $filename 已建立。"

wg