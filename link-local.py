import subprocess

def collect_information():
    peer_name = input("请输入您的 peer 名：")
    user_asn = input("请输入您的 ASN：")
    peer_asn = input("请输入对方的 ASN：")
    peer_wireguard_public_key = input("请输入对方的 WireGuard 公钥：")
    peer_wireguard_endpoint = input("请输入对方的 WireGuard Endpoint：")
    user_wireguard_private_key = input("请输入您的 WireGuard 私钥：")
    user_wireguard_listen_port = input("请输入您的 WireGuard 监听端口（一般是对方ASN后五位）：")
    
    return {
        "peer_name": peer_name,
        "user_asn": user_asn,
        "peer_asn": peer_asn,
        "peer_wireguard_public_key": peer_wireguard_public_key,
        "peer_wireguard_endpoint": peer_wireguard_endpoint,
        "user_wireguard_private_key": user_wireguard_private_key,
        "user_wireguard_listen_port": user_wireguard_listen_port
    }

def generate_wireguard_config(peer_name, user_asn, user_wireguard_private_key, user_wireguard_listen_port, peer_wireguard_public_key, peer_wireguard_endpoint):
    config_template = f'''
[Interface]
PrivateKey = {user_wireguard_private_key}
ListenPort = {user_wireguard_listen_port}
PostUp = ip addr add fe80::{user_asn[-4:]}/64 dev %i
Table = off

[Peer]
PublicKey = {peer_wireguard_public_key}
Endpoint = {peer_wireguard_endpoint}
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64
'''

    # 将配置写入文件
    with open(f"/etc/wireguard/{peer_name}.conf", "w") as file:
        file.write(config_template)

    print(f"WireGuard 配置文件已生成并保存至 /etc/wireguard/{peer_name}.conf")

def generate_bgp_config(peer_name, user_asn, peer_asn, peer_wireguard_endpoint):
    config_template = f'''
protocol bgp {peer_name} from dnpeers {{
    neighbor fe80::{peer_asn[-4:]}%"{peer_name}" as {peer_asn};
    direct;
}}'''

    # 将配置写入文件
    with open(f"/etc/bird/peers/{peer_name}.conf", "w") as file:
        file.write(config_template)

    print(f"BGP 配置文件已生成并保存至 /etc/bird/peers/{peer_name}.conf")

def enable_wireguard_service(peer_name):
    subprocess.run(["systemctl", "enable", f"wg-quick@{peer_name}.service"])
    subprocess.run(["service", f"wg-quick@{peer_name}", "start"])

def restart_bird_service():
    subprocess.run(["birdc", "c"])
    subprocess.run(["birdc", "s", "p"])

def main():
    information = collect_information()
    generate_wireguard_config(
        information["peer_name"],
        information["user_asn"],
        information["user_wireguard_private_key"],
        information["user_wireguard_listen_port"],
        information["peer_wireguard_public_key"],
        information["peer_wireguard_endpoint"]
    )
    generate_bgp_config(
        information["peer_name"],
        information["user_asn"],
        information["peer_asn"],
        information["peer_wireguard_endpoint"]
    )
    enable_wireguard_service(information["peer_name"])
    restart_bird_service()

if __name__ == "__main__":
    main()
