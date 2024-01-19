import requests
import subprocess
import yaml
import os

def get_git_commit_hash():
    try:
        # 获取本地 Git 仓库的最新 commit hash，仅取前6位
        commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('utf-8').strip()
        return commit_hash
    except subprocess.CalledProcessError:
        # 如果发生错误（例如不在Git仓库中），返回默认字符串
        return "Unknown"

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
    print("创建新的BGP会话（仅v4）")

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
    with open(peer_config_path, 'w') as config_file:
        config_file.write(config_content)

    print(f"WireGuard配置 '{session_name}' 已保存到 '{peer_config_path}'.")
    
    # 执行相关命令
    subprocess.run(['sudo', 'systemctl', 'enable', f"wg-quick@{session_name}.service"])
    subprocess.run(['sudo', 'wg-quick', 'up', session_name])
    subprocess.run(['sudo', 'birdc', 'configure'])
    subprocess.run(['sudo', 'birdc', 'show', 'protocol'])

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

def main():
    while True:
        # 获取本地 Git 仓库的最新 commit hash，并在主菜单中显示前6位
        commit_hash = get_git_commit_hash()[:6]

        print(f"\nDN42 quickshell by sam\n版本号:v0.1.0( {commit_hash})")
        print("\n请选择功能:")
        print("1. 更新roa")
        print("2. 创建新的BGP会话（仅v4）")
        print("3. 保存你的节点信息")
        print("4. 从远程拉取更新并重启程序")
        print("5. 退出")

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
