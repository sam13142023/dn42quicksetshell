import requests
import subprocess
import yaml
import os
from typing import Dict, Optional, Any

CONFIG_FILE = 'dn42_config.yaml'

class DN42Config:
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file, return empty dict if file doesn't exist."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as file:
                    return yaml.safe_load(file) or {}
            except (yaml.YAMLError, IOError) as e:
                print(f"Error loading config file: {e}")
                return {}
        return {}

    def _save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as file:
                yaml.dump(self.config, file, default_flow_style=False, allow_unicode=True)
        except IOError as e:
            print(f"Error saving config file: {e}")

    def get_user_info(self) -> Optional[Dict[str, str]]:
        """Get user's basic information (ASN, keys, etc.)."""
        return self.config.get('user_info')

    def set_user_info(self, asn: str, private_key: str, dn42_ip: str, 
                      listen_port: str, dn42_ipv6: str = "", 
                      public_key: str = "", net_segment: str = "", 
                      net_segment_v6: str = ""):
        """Set user's basic information."""
        if 'user_info' not in self.config:
            self.config['user_info'] = {}
        
        self.config['user_info'].update({
            'asn': asn,
            'private_key': private_key,
            'dn42_ip': dn42_ip,
            'listen_port': listen_port,
            'dn42_ipv6': dn42_ipv6,
            'public_key': public_key,
            'net_segment': net_segment,
            'net_segment_v6': net_segment_v6
        })
        self._save_config()

    def get_peers(self) -> Dict[str, Dict[str, str]]:
        """Get all peer configurations."""
        return self.config.get('peers', {})

    def add_peer(self, peer_name: str, asn: str, public_key: str, 
                 endpoint: str, dn42_ip: str = ""):
        """Add or update a peer configuration."""
        if 'peers' not in self.config:
            self.config['peers'] = {}
        
        self.config['peers'][peer_name] = {
            'asn': asn,
            'public_key': public_key,
            'endpoint': endpoint,
            'dn42_ip': dn42_ip
        }
        self._save_config()

    def get_peer(self, peer_name: str) -> Optional[Dict[str, str]]:
        """Get specific peer configuration."""
        return self.config.get('peers', {}).get(peer_name)

    def remove_peer(self, peer_name: str) -> bool:
        """Remove a peer configuration."""
        if 'peers' in self.config and peer_name in self.config['peers']:
            del self.config['peers'][peer_name]
            self._save_config()
            return True
        return False

    def is_initialized(self) -> bool:
        """Check if user configuration is initialized."""
        user_info = self.get_user_info()
        if not user_info:
            return False
        
        required_fields = ['asn', 'private_key', 'dn42_ip', 'listen_port']
        return all(user_info.get(field) for field in required_fields)

    def list_peers(self) -> list:
        """List all configured peer names."""
        return list(self.config.get('peers', {}).keys())

    def export_config(self) -> str:
        """Export configuration as YAML string."""
        return yaml.dump(self.config, default_flow_style=False, allow_unicode=True)

    def clear_config(self):
        """Clear all configuration."""
        self.config = {}
        self._save_config()

def get_git_commit_hash():
    try:
        # 获取本地 Git 仓库的最新 commit hash，仅取前6位
        commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('utf-8').strip()
        return commit_hash
    except subprocess.CalledProcessError:
        # 如果发生错误（例如不在Git仓库中），返回默认字符串
        return "Unknown"

def init_user_config():
    """初始化用户配置信息"""
    print("=== DN42 用户配置初始化 ===")
    print("请输入您的基本信息，这些信息将保存在本地配置中。")
    
    config = DN42Config()
    
    asn = input("请输入您的 ASN 号码: ")
    private_key = input("请输入您的 WireGuard 私钥: ")
    dn42_ip = input("请输入您的 DN42 IPv4 地址: ")
    listen_port = input("请输入您的 WireGuard 监听端口: ")
    
    # 可选信息
    print("\n以下信息为可选，可直接回车跳过:")
    dn42_ipv6 = input("请输入您的 DN42 IPv6 地址 (可选): ")
    public_key = input("请输入您的 WireGuard 公钥 (可选): ")
    net_segment = input("请输入您的 IPv4 网段 (可选): ")
    net_segment_v6 = input("请输入您的 IPv6 网段 (可选): ")
    
    config.set_user_info(
        asn=asn,
        private_key=private_key,
        dn42_ip=dn42_ip,
        listen_port=listen_port,
        dn42_ipv6=dn42_ipv6,
        public_key=public_key,
        net_segment=net_segment,
        net_segment_v6=net_segment_v6
    )
    
    print(f"\n用户配置已保存到 {config.config_file}")
    print("现在您可以使用快速模式创建新的 BGP 会话，只需要输入对端信息。")

def show_user_config():
    """显示当前用户配置"""
    config = DN42Config()
    user_info = config.get_user_info()
    
    if not user_info:
        print("尚未配置用户信息。请先使用初始化功能。")
        return
    
    print("=== 当前用户配置 ===")
    print(f"ASN: {user_info.get('asn', 'N/A')}")
    print(f"DN42 IPv4: {user_info.get('dn42_ip', 'N/A')}")
    print(f"DN42 IPv6: {user_info.get('dn42_ipv6', 'N/A')}")
    print(f"WireGuard 监听端口: {user_info.get('listen_port', 'N/A')}")
    print(f"IPv4 网段: {user_info.get('net_segment', 'N/A')}")
    print(f"IPv6 网段: {user_info.get('net_segment_v6', 'N/A')}")
    
    # 不显示私钥的完整内容，只显示前后几位
    private_key = user_info.get('private_key', '')
    if private_key:
        if len(private_key) > 10:
            masked_key = private_key[:4] + "..." + private_key[-4:]
        else:
            masked_key = "***"
        print(f"WireGuard 私钥: {masked_key}")

def manage_peer_configs():
    """管理对端配置"""
    config = DN42Config()
    
    while True:
        print("\n=== 对端配置管理 ===")
        print("1. 查看所有对端")
        print("2. 查看特定对端")
        print("3. 删除对端配置")
        print("4. 返回主菜单")
        
        choice = input("请选择功能: ")
        
        if choice == '1':
            peers = config.get_peers()
            if not peers:
                print("暂无保存的对端配置。")
            else:
                print("\n已保存的对端:")
                for peer_name, peer_info in peers.items():
                    print(f"  {peer_name}: ASN {peer_info.get('asn', 'N/A')}, IP {peer_info.get('dn42_ip', 'N/A')}")
        
        elif choice == '2':
            peer_name = input("请输入对端名称: ")
            peer_info = config.get_peer(peer_name)
            if peer_info:
                print(f"\n对端 {peer_name} 的配置:")
                for key, value in peer_info.items():
                    print(f"  {key}: {value}")
            else:
                print(f"未找到对端 {peer_name} 的配置。")
        
        elif choice == '3':
            peer_name = input("请输入要删除的对端名称: ")
            if config.remove_peer(peer_name):
                print(f"已删除对端 {peer_name} 的配置。")
            else:
                print(f"未找到对端 {peer_name} 的配置。")
        
        elif choice == '4':
            break
        
        else:
            print("无效的选择，请重新输入。")

def update_roa_script():
    url = 'https://sam1314.com/dn42/upgraderoa.sh'
    response = requests.get(url)

    with open('upgraderoa.sh', 'wb') as file:
        file.write(response.content)

    # 添加执行权限
    subprocess.run(['chmod', '+x', 'upgraderoa.sh'])

    # 执行脚本
    subprocess.run(['./upgraderoa.sh'])

def create_new_bgp_session():
    """创建新的BGP会话，支持快速模式（使用已保存的用户配置）"""
    config = DN42Config()
    user_info = config.get_user_info()
    
    if not config.is_initialized():
        print("检测到用户配置未初始化。")
        init_choice = input("是否现在初始化用户配置？(y/n): ")
        if init_choice.lower() == 'y':
            init_user_config()
            user_info = config.get_user_info()
        else:
            print("将使用传统模式（每次输入完整信息）。")
            create_new_bgp_session_legacy()
            return
    
    print("=== 创建新的BGP会话（快速模式）===")
    print("使用已保存的用户配置，只需要输入对端信息。")
    
    # 显示当前用户信息
    print(f"\n您的信息: ASN {user_info['asn']}, IP {user_info['dn42_ip']}")
    
    # 输入对端信息
    session_name = input("请输入BGP会话名称: ")
    peer_asn = input("请输入对方的ASN: ")
    peer_dn42_ip = input("请输入对方的DN42 IP: ")
    peer_wg_public_key = input("请输入对方的WireGuard公钥: ")
    peer_wg_listen_address = input("请输入对方的WireGuard监听地址: ")
    
    # 保存对端配置
    config.add_peer(session_name, peer_asn, peer_wg_public_key, 
                   peer_wg_listen_address, peer_dn42_ip)
    
    # 使用用户配置和对端信息生成WireGuard配置
    config_content = f"""[Interface]
PrivateKey = {user_info['private_key']}
ListenPort = {user_info['listen_port']}
PostUp = ip addr add {user_info['dn42_ip']} peer {peer_dn42_ip} dev %i
Table = off

[Peer]
PublicKey = {peer_wg_public_key}
Endpoint = {peer_wg_listen_address}
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64
"""

    # 保存WireGuard配置到文件
    peer_config_path = f"/etc/wireguard/{session_name}.conf"
    try:
        with open(peer_config_path, 'w') as config_file:
            config_file.write(config_content)
        print(f"WireGuard配置 '{session_name}' 已保存到 '{peer_config_path}'.")
    except PermissionError:
        print(f"权限不足，无法写入 {peer_config_path}")
        print("配置内容:")
        print(config_content)
        return
    except Exception as e:
        print(f"保存配置文件时出错: {e}")
        return
    
    # 执行相关命令
    try:
        subprocess.run(['sudo', 'systemctl', 'enable', f"wg-quick@{session_name}.service"])
        subprocess.run(['sudo', 'wg-quick', 'up', session_name])
        subprocess.run(['sudo', 'birdc', 'configure'])
        subprocess.run(['sudo', 'birdc', 'show', 'protocol'])
        print(f"BGP会话 '{session_name}' 创建完成！")
    except Exception as e:
        print(f"执行系统命令时出错: {e}")

def create_new_bgp_session_legacy():
    """创建新的BGP会话（传统模式，每次输入完整信息）"""
    print("创建新的BGP会话（传统模式）")

    session_name = input("请输入BGP会话名称: ")
    peer_asn = input("请输入对方的ASN: ")
    peer_dn42_ip = input("请输入对方的DN42 IP: ")
    your_dn42_ip = input("请输入你的DN42 IP: ")
    your_wg_private_key = input("请输入你的WireGuard私钥: ")
    peer_wg_public_key = input("请输入对方的WireGuard公钥: ")

    # 用户输入对方的WireGuard监听地址
    peer_wg_listen_address = input("请输入对方的WireGuard监听地址: ")

    # 用户输入WireGuard监听端口
    wg_listen_port = input("请输入WireGuard监听端口: ")

    # 将WireGuard配置写入文件
    config_content = f"""[Interface]
PrivateKey = {your_wg_private_key}
ListenPort = {wg_listen_port}
PostUp = ip addr add {your_dn42_ip} peer {peer_dn42_ip} dev %i
Table = off

[Peer]
PublicKey = {peer_wg_public_key}
Endpoint = {peer_wg_listen_address}
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64
"""

    # 保存WireGuard配置到文件
    peer_config_path = f"/etc/wireguard/{session_name}.conf"
    try:
        with open(peer_config_path, 'w') as config_file:
            config_file.write(config_content)
        print(f"WireGuard配置 '{session_name}' 已保存到 '{peer_config_path}'.")
    except PermissionError:
        print(f"权限不足，无法写入 {peer_config_path}")
        print("配置内容:")
        print(config_content)
        return
    except Exception as e:
        print(f"保存配置文件时出错: {e}")
        return
    
    # 执行相关命令
    try:
        subprocess.run(['sudo', 'systemctl', 'enable', f"wg-quick@{session_name}.service"])
        subprocess.run(['sudo', 'wg-quick', 'up', session_name])
        subprocess.run(['sudo', 'birdc', 'configure'])
        subprocess.run(['sudo', 'birdc', 'show', 'protocol'])
    except Exception as e:
        print(f"执行系统命令时出错: {e}")

def save_node_info():
    print("保存你的节点信息")

    # 二级菜单
    print("\n请选择相关功能:")
    print("1. 输入ASN号码")
    print("2. 输入具体的DN42节点信息")
    print("3. 返回主菜单")

    node_info = {'basicinfo': {}}

    while True:
        sub_choice = input("输入数字以选择功能: ")

        if sub_choice == '1':
            asn_num = input("请输入你的ASN号码: ")
            node_info['basicinfo']['asnnum'] = asn_num
            print("ASN号码已保存.")
        elif sub_choice == '2':
            node_name = input("请输入你的DN42节点名称: ")
            dn42_ip = input("请输入你的DN42 IP: ")
            wireguard_key = input("请输入你的WireGuard私钥: ")

            node_info[node_name] = {
                'dn42ip': dn42_ip,
                'wireguardkey': wireguard_key
            }
            print(f"{node_name} 的节点信息已保存.")
        elif sub_choice == '3':
            break
        else:
            print("无效的选择，请重新输入。")

    with open('node.yaml', 'w') as yaml_file:
        yaml.dump(node_info, yaml_file, default_flow_style=False)

    print("节点信息已保存到 'node.yaml'.")

def pull_and_restart():
    print("正在拉取更新...")
    subprocess.run(['git', 'pull', 'origin', 'main'])
    print("更新已成功拉取。重启程序...")
    subprocess.run(['python3', 'bash.py'])
    exit()

def update_bird_config():
    """设置 BIRD 配置文件，支持使用已保存的用户配置"""
    config = DN42Config()
    user_info = config.get_user_info()
    
    if user_info and user_info.get('asn') and user_info.get('dn42_ip'):
        print("检测到已保存的用户配置。")
        use_saved = input("是否使用已保存的配置？(y/n): ")
        
        if use_saved.lower() == 'y':
            own_as = user_info['asn']
            own_ip = user_info['dn42_ip']
            own_ipv6 = user_info.get('dn42_ipv6', '')
            own_net = user_info.get('net_segment', '')
            own_net_v6 = user_info.get('net_segment_v6', '')
            
            # 如果某些字段为空，询问用户
            if not own_ipv6:
                own_ipv6 = input("请输入想要宣告的IPv6: ")
            if not own_net:
                own_net = input("请输入你的IP段: ")
            if not own_net_v6:
                own_net_v6 = input("请输入你的IPv6段: ")
        else:
            # 手动输入所有信息
            own_as = input("请输入你的asn: ")
            own_ip = input("请输入想要宣告IP: ")
            own_ipv6 = input("请输入想要宣告的IPv6: ")
            own_net = input("请输入你的IP段: ")
            own_net_v6 = input("请输入你的IPv6段: ")
    else:
        print("设置 BIRD 配置文件")
        # 获取用户输入的信息
        own_as = input("请输入你的asn: ")
        own_ip = input("请输入想要宣告IP: ")
        own_ipv6 = input("请输入想要宣告的IPv6: ")
        own_net = input("请输入你的IP段: ")
        own_net_v6 = input("请输入你的IPv6段: ")

    # 读取示例配置文件
    example_conf_path = os.path.join(os.path.dirname(__file__), 'exampleconf')
    try:
        with open(example_conf_path, 'r') as example_conf_file:
            example_conf_content = example_conf_file.read()
    except FileNotFoundError:
        print(f"错误：找不到示例配置文件 {example_conf_path}")
        return
    except Exception as e:
        print(f"读取示例配置文件时出错: {e}")
        return

    # 替换示例配置文件中的信息
    updated_conf_content = example_conf_content.replace("$OWNAS", own_as)\
                                               .replace("$OWNIP", own_ip)\
                                               .replace("$OWNIPv6", own_ipv6)\
                                               .replace("$OWNNET", own_net)\
                                               .replace("$OWNNETv6", own_net_v6)

    # 检查是否存在旧的配置文件，如果存在则备份
    bird_conf_path = '/etc/bird/bird.conf'
    if os.path.exists(bird_conf_path):
        backup_path = '/etc/bird/bird.conf.old'
        try:
            subprocess.run(['mv', bird_conf_path, backup_path])
            print(f"旧的配置文件已备份为 {backup_path}.")
        except Exception as e:
            print(f"备份配置文件时出错: {e}")

    # 将更新后的配置写入新的文件
    try:
        with open(bird_conf_path, 'w') as bird_conf_file:
            bird_conf_file.write(updated_conf_content)
        print(f"新的配置文件已保存到 {bird_conf_path}.")
    except PermissionError:
        print(f"权限不足，无法写入 {bird_conf_path}")
        print("配置内容:")
        print(updated_conf_content)
    except Exception as e:
        print(f"保存配置文件时出错: {e}")

def create_wireguard_tunnel():
    """创建 WireGuard 隧道 (替代 newwg.sh)"""
    print("=== 创建 WireGuard 隧道 ===")
    
    tunnel_name = input("请输入隧道名：")
    private_key = input("请输入你的私钥：")
    listen_port = input("请输入你监听的端口：")
    your_dn42_ip = input("请输入你的dn42 IP：")
    peer_dn42_ip = input("请输入对方的dn42 IP：")
    peer_public_key = input("请输入对方的公钥：")
    peer_endpoint = input("请输入对方的endpoint：")

    content = f"""[Interface]
PrivateKey = {private_key}
ListenPort = {listen_port}
PostUp = ip addr add {your_dn42_ip} peer {peer_dn42_ip} dev %i
Table = off

[Peer]
PublicKey = {peer_public_key}
Endpoint = {peer_endpoint}
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64"""

    config_path = f"/etc/wireguard/{tunnel_name}.conf"
    try:
        with open(config_path, 'w') as file:
            file.write(content)
        print(f"内容已写入到 {config_path} 文件中。")
        
        # 启用服务和启动隧道
        subprocess.run(['sudo', 'systemctl', 'enable', f"wg-quick@{tunnel_name}"], check=True)
        subprocess.run(['sudo', 'wg-quick', 'up', tunnel_name], check=True)
        print(f"隧道 {tunnel_name} 已建立。")
        
        # 显示WireGuard状态
        subprocess.run(['sudo', 'wg'], check=False)
        
    except PermissionError:
        print(f"权限不足，无法写入 {config_path}")
        print("配置内容:")
        print(content)
    except subprocess.CalledProcessError as e:
        print(f"执行系统命令时出错: {e}")
    except Exception as e:
        print(f"创建隧道时出错: {e}")

def create_bgp_peer():
    """创建 BGP 对等配置 (替代 newbgp.sh)"""
    print("=== 创建 BGP 对等配置 ===")
    
    dn42ip = input("请输入对方的dn42ip: ")
    asn = input("请输入对方的ASN: ")
    bgp_name = input("请输入BGP会话名字: ")

    config_content = f"""
protocol bgp {bgp_name} from dnpeers {{
    neighbor {dn42ip} as {asn};
    ipv4 {{
        next hop self;
        extended next hop on;
    }};
}}
"""

    config_file = f"/etc/bird/peers/{bgp_name}.conf"
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        with open(config_file, 'w') as file:
            file.write(config_content)
        print(f"BGP配置已写入 {config_file}")
        
        # 重载BIRD配置
        subprocess.run(['sudo', 'birdc', 'configure'], check=True)
        subprocess.run(['sudo', 'birdc', 'show', 'protocol'], check=True)
        
    except PermissionError:
        print(f"权限不足，无法写入 {config_file}")
        print("配置内容:")
        print(config_content)
    except subprocess.CalledProcessError as e:
        print(f"执行BIRD命令时出错: {e}")
    except Exception as e:
        print(f"创建BGP配置时出错: {e}")

def setup_peer_complete():
    """完整的对等点设置 (替代 setapeer.sh)"""
    print("=== 完整对等点设置 ===")
    print("这将引导您完成 WireGuard 隧道和 BGP 对等的完整设置。")
    
    # 执行WireGuard隧道创建
    print("\n步骤1: 创建 WireGuard 隧道")
    create_wireguard_tunnel()
    
    print("\n步骤2: 创建 BGP 对等配置")
    create_bgp_peer()
    
    print("\n✅ 对等点设置完成！")

def linklocal_bgp_setup():
    """Link-Local BGP 配置模式 (替代 link-local.py)"""
    print("=== Link-Local BGP 配置模式 ===")
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
    
    # 生成Link-Local WireGuard配置
    config_template = f'''
[Interface]
PrivateKey = {information["user_wireguard_private_key"]}
ListenPort = {information["user_wireguard_listen_port"]}
PostUp = ip addr add fe80::{information["user_asn"][-4:]}/64 dev %i
Table = off

[Peer]
PublicKey = {information["peer_wireguard_public_key"]}
Endpoint = {information["peer_wireguard_endpoint"]}
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64
'''

    # 将WireGuard配置写入文件
    config_path = f"/etc/wireguard/{peer_name}.conf"
    try:
        with open(config_path, "w") as file:
            file.write(config_template)
        print(f"WireGuard 配置文件已生成并保存至 {config_path}")
    except PermissionError:
        print(f"权限不足，无法写入 {config_path}")
        print("配置内容:")
        print(config_template)
        return
    except Exception as e:
        print(f"生成WireGuard配置文件时出错: {e}")
        return

    # 生成Link-Local BGP配置
    bgp_config_template = f'''
protocol bgp {peer_name} from dnpeers {{
    neighbor fe80::{peer_asn[-4:]}%"{peer_name}" as {peer_asn};
    direct;
}}'''

    # 将BGP配置写入文件
    bgp_config_path = f"/etc/bird/peers/{peer_name}.conf"
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(bgp_config_path), exist_ok=True)
        
        with open(bgp_config_path, "w") as file:
            file.write(bgp_config_template)
        print(f"BGP 配置文件已生成并保存至 {bgp_config_path}")
    except PermissionError:
        print(f"权限不足，无法写入 {bgp_config_path}")
        print("配置内容:")
        print(bgp_config_template)
        return
    except Exception as e:
        print(f"生成BGP配置文件时出错: {e}")
        return

    # 启用WireGuard服务
    try:
        subprocess.run(["systemctl", "enable", f"wg-quick@{peer_name}.service"], check=True)
        subprocess.run(["service", f"wg-quick@{peer_name}", "start"], check=True)
        print(f"WireGuard服务 {peer_name} 已启用并启动")
    except subprocess.CalledProcessError as e:
        print(f"启用WireGuard服务时出错: {e}")
    except Exception as e:
        print(f"启用WireGuard服务时发生未知错误: {e}")

    # 重启BIRD服务
    try:
        subprocess.run(["birdc", "c"], check=True)
        subprocess.run(["birdc", "s", "p"], check=True)
        print("BIRD服务已重新配置")
    except subprocess.CalledProcessError as e:
        print(f"重启BIRD服务时出错: {e}")
    except Exception as e:
        print(f"重启BIRD服务时发生未知错误: {e}")

    print("\n✅ Link-Local BGP 配置完成！")

def main():
    config = DN42Config()
    
    while True:
        # 获取本地 Git 仓库的最新 commit hash，并在主菜单中显示前6位
        commit_hash = get_git_commit_hash()[:6]

        print(f"\nDN42 quickshell by sam\n版本号: v0.1.0 ({commit_hash})")
        
        # 显示配置状态
        if config.is_initialized():
            user_info = config.get_user_info()
            print(f"✓ 已配置用户信息 (ASN: {user_info['asn']})")
        else:
            print("⚠ 尚未配置用户信息")
        
        print("\n请选择功能:")
        print("1. 更新roa")
        print("2. 创建新的BGP会话")
        print("3. 保存你的节点信息 (旧版本兼容)")
        print("4. 从远程拉取更新并重启程序")
        print("5. 更新 BIRD 配置文件")
        print("6. 初始化用户配置")
        print("7. 查看用户配置")
        print("8. 管理对端配置")
        print("9. 创建 WireGuard 隧道")
        print("10. 创建 BGP 对等配置")
        print("11. 完整对等点设置")
        print("12. Link-Local BGP 配置")
        print("13. 退出")

        choice = input("输入数字以选择功能: ")

        if choice == '1':
            update_roa_script()
        elif choice == '2':
            create_new_bgp_session()
        elif choice == '3':
            save_node_info()
        elif choice == '4':
            pull_and_restart()
        elif choice == '5':
            update_bird_config()
        elif choice == '6':
            init_user_config()
        elif choice == '7':
            show_user_config()
        elif choice == '8':
            manage_peer_configs()
        elif choice == '9':
            create_wireguard_tunnel()
        elif choice == '10':
            create_bgp_peer()
        elif choice == '11':
            setup_peer_complete()
        elif choice == '12':
            linklocal_bgp_setup()
        elif choice == '13':
            print("程序结束。")
            break
        else:
            print("无效的选择，请重新输入。")

        # 添加用户选择是否继续的逻辑
        continue_choice = input("是否继续？(输入 'y' 继续，其他键退出): ")
        if continue_choice.lower() != 'y':
            print("程序结束。")
            break

if __name__ == "__main__":
    main()
