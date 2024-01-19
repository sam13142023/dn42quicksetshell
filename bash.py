import requests
import subprocess

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

def main():
    while True:
        print("\n选择一个功能:")
        print("1. 更新roa")
        print("2. 创建新的BGP会话（仅v4）")
        print("3. 退出")

        choice = input("输入数字以选择功能: ")

        if choice == '1':
            update_roa_script()
        elif choice == '2':
            create_new_bgp_session()
        elif choice == '3':
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

