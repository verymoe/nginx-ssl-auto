import os
import re
import subprocess
import glob
import psutil
import logging
import argparse
import shutil
import datetime
from typing import List, Dict, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning
from prettytable import PrettyTable
import time

VERSION = "0.0.2"
REPO_URL = "https://github.com/verymoe/nginx-ssl-auto"
AUTHOR = "Shiro"

# 禁用不安全请求的警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_version():
    print(f"nginx-ssl-auto 版本 {VERSION}")

def find_nginx_processes(debug: bool) -> List[Tuple[str, str]]:
    nginx_processes = []
    if debug:
        logger.debug("开始查找 Nginx 进程...")
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            if proc.info['name'] == 'nginx':
                if debug:
                    logger.debug(f"找到 Nginx 进程: PID={proc.info['pid']}")
                exe = proc.info['exe']
                conf_path = None
                if 'nginx: master process' in ' '.join(proc.info['cmdline']):
                    for i, arg in enumerate(proc.info['cmdline']):
                        if arg == '-c':
                            conf_path = proc.info['cmdline'][i+1]
                            break
                if exe and conf_path:
                    nginx_processes.append((exe, conf_path))
                    if debug:
                        logger.debug(f"添加 Nginx 进程信息: 可执行文件={exe}, 配置文件={conf_path}")

        if nginx_processes:
            logger.info(f"找到 {len(nginx_processes)} 个 Nginx 进程")
            for exe, conf in nginx_processes:
                logger.info(f"Nginx 可执行文件: {exe}, 配置文件: {conf}")
        else:
            logger.warning("未找到 Nginx 进程")
    except Exception as e:
        logger.error(f"查找 Nginx 进程时出错: {e}")

    return nginx_processes

def find_included_conf_files(main_conf_path: str, debug: bool) -> List[str]:
    if debug:
        logger.debug(f"开始查找包含的配置文件，主配置文件: {main_conf_path}")
    if not main_conf_path or not os.path.exists(main_conf_path):
        logger.error(f"未找到主配置文件: {main_conf_path}")
        return []

    conf_files = [main_conf_path]
    dir_path = os.path.dirname(main_conf_path)

    try:
        with open(main_conf_path, 'r') as f:
            for line in f:
                if line.strip().startswith('include'):
                    include_path = line.split()[1].strip(';')
                    if not os.path.isabs(include_path):
                        include_path = os.path.join(dir_path, include_path)
                    included_files = glob.glob(include_path)
                    conf_files.extend(included_files)
                    if debug:
                        logger.debug(f"找到包含的配置文件: {included_files}")
    except Exception as e:
        logger.error(f"读取主配置文件时出错: {e}")

    if debug:
        logger.debug(f"找到的所有配置文件: {conf_files}")
    return conf_files

def get_cert_expiry(cert_path: str, debug: bool) -> Optional[str]:
    if debug:
        logger.debug(f"开始获取证书过期时间: {cert_path}")
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        expiry_date = cert.not_valid_after_utc
        expiry_str = expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC')
        if debug:
            logger.debug(f"证书 {cert_path} 的过期时间: {expiry_str}")
        return expiry_str
    except Exception as e:
        logger.error(f"读取证书 {cert_path} 时出错: {e}")
        return None

def find_ssl_paths_and_hosts(conf_files: List[str], debug: bool) -> Dict[str, Dict]:
    ssl_info = {}
    for conf_file in conf_files:
        if debug:
            logger.debug(f"开始解析配置文件: {conf_file}")
        try:
            with open(conf_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # 移除注释
                content = re.sub(r'#.*$', '', content, flags=re.MULTILINE)

                # 在整个文件中查找SSL配置
                ssl_certificate = re.findall(r'ssl_certificate\s+(.*?);', content)
                ssl_certificate_key = re.findall(r'ssl_certificate_key\s+(.*?);', content)
                server_name = re.findall(r'server_name\s+(.*?);', content)

                if ssl_certificate or ssl_certificate_key:
                    hosts = [host.strip() for host in server_name[0].split()] if server_name else []
                    cert_path = ssl_certificate[0] if ssl_certificate else None
                    expiry = get_cert_expiry(cert_path, debug) if cert_path else None

                    ssl_info[conf_file] = {
                        'ssl_certificate': ssl_certificate[0] if ssl_certificate else None,
                        'ssl_certificate_key': ssl_certificate_key[0] if ssl_certificate_key else None,
                        'hosts': hosts,
                        'expiry': expiry
                    }
                    if debug:
                        logger.debug(f"在 {conf_file} 中找到 SSL 配置: {ssl_info[conf_file]}")
        except Exception as e:
            logger.error(f"读取配置文件 {conf_file} 时出错: {e}")
    if debug:
        logger.debug(f"所有找到的 SSL 信息: {ssl_info}")
    return ssl_info

def get_cloud_certificates(api_token: str, api_user: str, debug: bool) -> List[Dict]:
    url = "https://api.xwamp.com/api/user/Order/list"
    headers = {
        "Authorization": f"Bearer {api_token}:{api_user}"
    }

    if debug:
        logger.debug(f"开始获取云证书，API URL: {url}")

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        if data['isOk']:
            if debug:
                logger.debug(f"成功获取云证书，数量: {len(data['data']['list'])}")
            return data['data']['list']
        else:
            error_message = data.get('error', '未知错误')
            if error_message == "no auth":
                logger.error("认证失败。请检查您的 API_TOKEN 和 API_USER。")
            else:
                logger.error(f"获取云证书时出错: {error_message}")
            return []
    except RequestException as e:
        logger.error(f"获取云证书时出错: {e}")
        return []

def match_certificates(local_ssl_info: Dict[str, Dict], cloud_certs: List[Dict], debug: bool) -> List[Dict]:
    matched_certs = []
    if debug:
        logger.debug("开始匹配本地证书和云证书")

    for conf_file, local_cert in local_ssl_info.items():
        matched_cloud_cert = None
        for cloud_cert in cloud_certs:
            # if set(local_cert['hosts']) & set(cloud_cert['domains']):
            #     matched_cloud_cert = cloud_cert
            #     if debug:
            #         logger.debug(f"本地证书 {conf_file} 与云证书 {cloud_cert['id']} 匹配")
            #     break
            # 使用更灵活的匹配方法，支持通配符域名
            if any(match_domain(local_host, cloud_domain)
                   for local_host in local_cert['hosts']
                   for cloud_domain in cloud_cert['domains']):
                matched_cloud_cert = cloud_cert
                if debug:
                    logger.debug(f"本地证书 {conf_file} 与云证书 {cloud_cert['id']} 匹配")
                break

        matched_certs.append({
            'local_cert': {
                'file': conf_file,
                'hosts': local_cert['hosts'],
                'expiry': local_cert['expiry'],
                'ssl_certificate': local_cert['ssl_certificate'],
                'ssl_certificate_key': local_cert['ssl_certificate_key']
            },
            'cloud_cert': matched_cloud_cert,
            'expiry_match': local_cert['expiry'] == (matched_cloud_cert['time_end'] if matched_cloud_cert else None)
        })

    if debug:
        logger.debug(f"匹配结果: {matched_certs}")
    return matched_certs

def match_domain(local_domain: str, cloud_domain: str) -> bool:
    if cloud_domain.startswith('*.'):
        return local_domain.endswith(cloud_domain[2:]) or local_domain == cloud_domain[2:]
    return local_domain == cloud_domain

def get_expected_action(cert: Dict, debug: bool) -> Tuple[str, str]:
    if debug:
        logger.debug(f"开始确定预期操作: {cert}")
    if not cert['cloud_cert']:
        return "NO_REPLACE_NO_MATCH", "不替换：云端无匹配"
    if cert['cloud_cert']['status'] == 3 and cert['cloud_cert']['status_name'] == "验证中":
        return "NO_REPLACE_VALIDATING", "不替换：云端证书正在申请中"

    local_expiry = datetime.datetime.strptime(cert['local_cert']['expiry'], '%Y-%m-%d %H:%M:%S UTC')
    cloud_expiry = datetime.datetime.strptime(cert['cloud_cert']['time_end'], '%Y-%m-%d %H:%M:%S')

    time_difference = abs(cloud_expiry - local_expiry)

    if time_difference < datetime.timedelta(hours=24):
        return "NO_REPLACE_SIMILAR", "不替换：有效期相差不到24小时"
    elif cloud_expiry < local_expiry:
        return "NO_REPLACE_LOCAL_NEWER", "不替换：本地证书有效期更新"
    elif cloud_expiry > local_expiry:
        return "REPLACE", "将替换：云端证书有效期更新"
    else:
        return "NO_REPLACE_UNKNOWN", "不替换：无法判断，请反馈"

def print_certificate_table(matched_certs: List[Dict], debug: bool):
    if debug:
        logger.debug("开始打印证书匹配表格")
    table = PrettyTable()
    table.field_names = ["本地主机", "本地过期时间", "云端域名", "云端过期时间", "预期操作"]
    table.align = "l"
    table.max_width = 30

    for i, cert in enumerate(matched_certs):
        local_hosts = ", ".join(cert['local_cert']['hosts'])
        local_expiry = cert['local_cert']['expiry']
        cloud_domains = ", ".join(cert['cloud_cert']['domains']) if cert['cloud_cert'] else "N/A"
        cloud_expiry = cert['cloud_cert']['time_end'] if cert['cloud_cert'] else "N/A"
        action, expected_action = get_expected_action(cert, debug)

        # 根据预期操作添加强调符号
        if action == "REPLACE":
            expected_action = "✓ " + expected_action
        elif action == "NO_REPLACE_LOCAL_NEWER":
            expected_action = "! " + expected_action
        elif action == "NO_REPLACE_UNKNOWN":
            expected_action = "? " + expected_action
        elif action == "NO_REPLACE_SIMILAR":
            expected_action = "- " + expected_action
        elif action == "NO_REPLACE_VALIDATING":
            expected_action = "* " + expected_action
        else:
            expected_action = "- " + expected_action

        # 将预期操作拆分成多行，以确保不超出表格边界
        expected_action_lines = [expected_action[i:i+28] for i in range(0, len(expected_action), 28)]

        # 添加第一行数据
        table.add_row([
            local_hosts,
            local_expiry,
            cloud_domains,
            cloud_expiry,
            expected_action_lines[0]
        ])

        # 如果预期操作有多行，添加剩余的行
        for line in expected_action_lines[1:]:
            table.add_row(["", "", "", "", "  " + line])  # 添加两个空格以对齐后续行

        # 在每个证书之间添加空行，除了最后一个证书
        if i < len(matched_certs) - 1:
            table.add_row([""] * 5)

    print(table)
    if debug:
        logger.debug("证书匹配表格已打印")

def ensure_backup_dir(debug: bool) -> str:
    backup_dir = os.path.join(os.getcwd(), "nginx-ssl-auto-bak")
    os.makedirs(backup_dir, exist_ok=True)
    if debug:
        logger.debug(f"确保备份目录存在: {backup_dir}")
    return backup_dir

def backup_certificate(cert_path: str, backup_dir: str, debug: bool) -> str:
    cert_name = os.path.basename(cert_path)
    backup_path = os.path.join(backup_dir, f"{cert_name}.bak")
    shutil.copy2(cert_path, backup_path)
    if debug:
        logger.debug(f"已备份证书: {cert_path} -> {backup_path}")
    return backup_path

def restore_certificate(backup_path: str, cert_path: str, debug: bool) -> None:
    shutil.copy2(backup_path, cert_path)
    if debug:
        logger.debug(f"已恢复证书: {backup_path} -> {cert_path}")

def replace_certificates(matched_certs: List[Dict], api_token: str, api_user: str, debug: bool) -> Tuple[bool, Dict[str, str]]:
    if debug:
        logger.debug("开始替换证书")

    backup_dir = ensure_backup_dir(debug)
    backups = {}
    replaced = False

    for cert in matched_certs:
        action, expected_action = get_expected_action(cert, debug)
        if action != "REPLACE":
            logger.info(f"{', '.join(cert['local_cert']['hosts'])} 的证书不需要替换: {expected_action}")
            continue

        try:
            # 备份当前证书和密钥
            cert_path = cert['local_cert']['ssl_certificate']
            key_path = cert['local_cert']['ssl_certificate_key']
            backups[cert_path] = backup_certificate(cert_path, backup_dir, debug)
            backups[key_path] = backup_certificate(key_path, backup_dir, debug)

            cert_url = "https://api.xwamp.com/api/user/OrderDetail/down"
            headers = {"Authorization": f"Bearer {api_token}:{api_user}"}
            params = {
                "id": cert['cloud_cert']['id'],
                "type": "json"
            }
            if debug:
                logger.debug(f"开始下载证书，URL: {cert_url}, 参数: {params}")
            response = requests.get(cert_url, headers=headers, params=params, verify=False)
            response.raise_for_status()

            cert_data = response.json()
            if not cert_data['isOk']:
                logger.error(f"下载证书失败: {cert_data.get('error', '未知错误')}")
                if cert_data.get('error') == 'no auth':
                    logger.error("API 认证失败。请检查 API_TOKEN 和 API_USER 是否正确。")
                continue

            cert_content = cert_data['data']['cert']
            key_content = cert_data['data']['key']

            if debug:
                logger.debug(f"开始写入新的证书文件: {cert_path}")
            with open(cert_path, 'w') as f:
                f.write(cert_content)

            if debug:
                logger.debug(f"开始写入新的密钥文件: {key_path}")
            with open(key_path, 'w') as f:
                f.write(key_content)

            logger.info(f"已替换 {', '.join(cert['local_cert']['hosts'])} 的证书。新的过期时间: {cert['cloud_cert']['time_end']}")
            replaced = True
        except requests.exceptions.RequestException as e:
            logger.error(f"API 请求失败: {e}")
        except Exception as e:
            logger.error(f"替换证书时出错: {e}")

        if not replaced:
            # 如果出错，恢复备份
            if cert_path in backups:
                restore_certificate(backups[cert_path], cert_path, debug)
            if key_path in backups:
                restore_certificate(backups[key_path], key_path, debug)

    return replaced, backups

def check_nginx_status(nginx_bin: str, debug: bool) -> bool:
    try:
        subprocess.run([nginx_bin, "-t"], check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        if debug:
            logger.debug(f"Nginx 配置测试失败: {e.stderr}")
        return False

def wait_for_nginx(nginx_bin: str, timeout: int = 30, debug: bool = False) -> bool:
    start_time = time.time()
    while time.time() - start_time < timeout:
        if check_nginx_status(nginx_bin, debug):
            return True
        time.sleep(1)
    return False

def is_reload_needed(matched_certs: List[Dict], debug: bool) -> bool:
    if debug:
        logger.debug("正在检查是否需要重新加载 Nginx")

    for cert in matched_certs:
        action, _ = get_expected_action(cert, debug)
        if action == "REPLACE":
            if debug:
                logger.debug("需要重新加载：至少有一个证书将被替换")
            return True

    if debug:
        logger.debug("无需重新加载：没有证书需要替换")
    return False

def reload_nginx(nginx_bin: str, debug: bool):
    if debug:
        logger.debug(f"开始重新加载 Nginx: {nginx_bin}")
    try:
        subprocess.run([nginx_bin, '-s', 'reload'], check=True)
        logger.info(f"Nginx ({nginx_bin}) 已成功重新加载")
    except subprocess.CalledProcessError as e:
        logger.error(f"重新加载 Nginx ({nginx_bin}) 失败: {e}")

def reload_and_verify_nginx(nginx_processes, backups, debug):
    """重载 Nginx 并验证其状态，如果失败则恢复备份"""
    for nginx_bin, _ in nginx_processes:
        reload_nginx(nginx_bin, debug)
        if wait_for_nginx(nginx_bin, debug=debug):
            logger.info("Nginx 重载成功，新证书已生效。")
        else:
            logger.warning("Nginx 重载后状态异常，正在尝试恢复备份...")
            restore_backups(backups, debug)

            # 再次尝试重载
            reload_nginx(nginx_bin, debug)
            if wait_for_nginx(nginx_bin, debug=debug):
                logger.warning("恢复备份后 Nginx 正常运行。不再尝试替换证书。请检查新证书是否有问题。")
            else:
                logger.error("恢复备份后 Nginx 仍然无法正常运行。请立即检查 Nginx 配置和证书。")

def restore_backups(backups, debug):
    """恢复所有备份的证书"""
    for local_path, backup_path in backups.items():
        restore_certificate(backup_path, local_path, debug)

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description="Nginx SSL 证书管理工具",
        epilog=f"版本: {VERSION}\n仓库: {REPO_URL}\n作者: {AUTHOR}"
    )
    parser.add_argument("--user", help="API 用户")
    parser.add_argument("--token", help="API 令牌")
    parser.add_argument("--replace", action="store_true", help="替换匹配的证书")
    parser.add_argument("--debug", action="store_true", help="启用调试模式")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print_version()

    # 设置日志级别
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("调试模式已启用")

    # 查找 Nginx 进程
    nginx_processes = find_nginx_processes(args.debug)
    if not nginx_processes:
        logger.error("未找到正在运行的 Nginx 进程")
        return

    # 收集本地 SSL 信息
    all_local_ssl_info = {}
    for nginx_bin, nginx_conf_path in nginx_processes:
        conf_files = find_included_conf_files(nginx_conf_path, args.debug)
        local_ssl_info = find_ssl_paths_and_hosts(conf_files, args.debug)
        all_local_ssl_info.update(local_ssl_info)

    # 如果提供了 API 凭据，则获取云端证书信息
    cloud_certs = []
    if args.user and args.token:
        cloud_certs = get_cloud_certificates(args.token, args.user, args.debug)
        if not cloud_certs:
            logger.warning("未检索到云证书。请检查您的 API 凭据和网络，使用 --debug 参数来打印更详细的日志。")
    else:
        logger.warning("您没有提供 API 账户和凭据，使用 --help 参数来获取更多信息。")

    # 匹配本地和云端证书
    matched_certs = match_certificates(all_local_ssl_info, cloud_certs, args.debug)

    # 打印证书匹配表格
    print("\n证书匹配表格:")
    print_certificate_table(matched_certs, args.debug)

    # 检查是否需要重载 Nginx
    reload_needed = is_reload_needed(matched_certs, args.debug)

    if args.replace:
        if reload_needed and args.user and args.token:
            logger.info("正在替换匹配的证书...")
            replaced, backups = replace_certificates(matched_certs, args.token, args.user, args.debug)
            if replaced:
                reload_and_verify_nginx(nginx_processes, backups, args.debug)
            else:
                logger.info("无需重新加载 Nginx：没有证书被替换")
        elif not args.user or not args.token:
            logger.warning("没有提供 API 凭据，无法替换证书。请提供 --user 和 --token。")
        else:
            logger.info("无需重新加载 Nginx：没有证书需要替换")
    else:
        if reload_needed:
            logger.info("检测到需要更新的证书。使用 --replace 参数来替换证书并自动重载 Nginx。")
        else:
            logger.info("没有匹配到需要更新的证书，无需进行额外操作。")

if __name__ == '__main__':
    main()