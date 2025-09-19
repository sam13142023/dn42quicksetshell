import subprocess
import os
from bash import DN42Config

def collect_information():
    """收集信息，支持使用已保存的用户配置"""
    config = DN42Config()
    user_info = config.get_user_info()
    
    # 初始化返回字典
    information = {}
    
    if config.is_initialized():
        print("检测到已保存的用户配置。")
        use_saved = input("是否使用已保存的用户配置？(y/n): ")
        
        if use_saved.lower() == 'y':
            # 使用已保存的用户信息
            information.update({
                "user_asn": user_info['asn'],
                "user_wireguard_private_key": user_info['private_key'],
                "user_wireguard_listen_port": user_info['listen_port']
            })
            print(f"使用已保存的配置: ASN {user_info['asn']}")
        else:
            # 手动输入用户信息
            information.update({
                "user_asn": input("请输入您的 ASN："),
                "user_wireguard_private_key": input("请输入您的 WireGuard 私钥："),
                "user_wireguard_listen_port": input("请输入您的 WireGuard 监听端口（一般是对方ASN后五位）：")
            })
    else:
        # 没有保存的配置，手动输入所有用户信息
        print("尚未检测到用户配置，请手动输入信息。")
        information.update({
            "user_asn": input("请输入您的 ASN："),
            "user_wireguard_private_key": input("请输入您的 WireGuard 私钥："),
            "user_wireguard_listen_port": input("请输入您的 WireGuard 监听端口（一般是对方ASN后五位）：")
        })
    
    # 总是需要输入的对端信息
    peer_name = input("请输入您的 peer 名：")
    peer_asn = input("请输入对方的 ASN：")
    peer_wireguard_public_key = input("请输入对方的 WireGuard 公钥：")
    peer_wireguard_endpoint = input("请输入对方的 WireGuard Endpoint：")
    
    information.update({
        "peer_name": peer_name,
        "peer_asn": peer_asn,
        "peer_wireguard_public_key": peer_wireguard_public_key,
        "peer_wireguard_endpoint": peer_wireguard_endpoint
    })
    
    # 保存对端信息到配置文件
    config.add_peer(peer_name, peer_asn, peer_wireguard_public_key, peer_wireguard_endpoint)
    print(f"对端 {peer_name} 的信息已保存到配置文件。")
    
    return information

def collect_information_legacy():
    """原始的信息收集函数，保持向后兼容"""
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
    config_path = f"/etc/wireguard/{peer_name}.conf"
    try:
        with open(config_path, "w") as file:
            file.write(config_template)
        print(f"WireGuard 配置文件已生成并保存至 {config_path}")
    except PermissionError:
        print(f"权限不足，无法写入 {config_path}")
        print("配置内容:")
        print(config_template)
    except Exception as e:
        print(f"生成WireGuard配置文件时出错: {e}")

def generate_bgp_config(peer_name, user_asn, peer_asn, peer_wireguard_endpoint):
    config_template = f'''
protocol bgp {peer_name} from dnpeers {{
    neighbor fe80::{peer_asn[-4:]}%"{peer_name}" as {peer_asn};
    direct;
}}'''

    # 将配置写入文件
    bgp_config_path = f"/etc/bird/peers/{peer_name}.conf"
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(bgp_config_path), exist_ok=True)
        
        with open(bgp_config_path, "w") as file:
            file.write(config_template)
        print(f"BGP 配置文件已生成并保存至 {bgp_config_path}")
    except PermissionError:
        print(f"权限不足，无法写入 {bgp_config_path}")
        print("配置内容:")
        print(config_template)
    except Exception as e:
        print(f"生成BGP配置文件时出错: {e}")

def enable_wireguard_service(peer_name):
    try:
        subprocess.run(["systemctl", "enable", f"wg-quick@{peer_name}.service"], check=True)
        subprocess.run(["service", f"wg-quick@{peer_name}", "start"], check=True)
        print(f"WireGuard服务 {peer_name} 已启用并启动")
    except subprocess.CalledProcessError as e:
        print(f"启用WireGuard服务时出错: {e}")
    except Exception as e:
        print(f"启用WireGuard服务时发生未知错误: {e}")

def restart_bird_service():
    try:
        subprocess.run(["birdc", "c"], check=True)
        subprocess.run(["birdc", "s", "p"], check=True)
        print("BIRD服务已重新配置")
    except subprocess.CalledProcessError as e:
        print(f"重启BIRD服务时出错: {e}")
    except Exception as e:
        print(f"重启BIRD服务时发生未知错误: {e}")

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
