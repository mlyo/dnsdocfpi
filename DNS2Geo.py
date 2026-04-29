import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import csv
import ipaddress
import os
import socket
import subprocess
import time

import dns.resolver
import requests


# =========================
# 配置常量
# =========================
MIN_DOWNLOAD_SPEED = 5.0

TCP_CHECK_PORT = 443
TCP_CHECK_TIMEOUT = 5

DNS_TIMEOUT = 10
DNS_LIFETIME = 15

IPINFO_TIMEOUT = 10
IPINFO_RETRIES = 10
IPINFO_RETRY_DELAY = 1

RESULT_WAIT_TIMEOUT = 600
RESULT_WAIT_INTERVAL = 2

SCANNER_DIR = "CloudflareScanner"
SCANNER_EXE = "CloudflareScanner.exe"
SCANNER_EXE_PATH = os.path.join(SCANNER_DIR, SCANNER_EXE)
SCANNER_IP_FILE = os.path.join(SCANNER_DIR, "ip.txt")
SCANNER_RESULT_CSV = os.path.join(SCANNER_DIR, "result.csv")

COUNTRIES_FILE = "countries.txt"
MANUAL_INPUT_IP_FILE = "Manual_input_IP.txt"
DOMAINS_FILE = "domains.txt"
ALLOWED_COUNTRIES_FILE = "allowed_countries.txt"

IPS_DIR = "ips"
IPS_WITH_COUNTRY_DIR = "ips_with_country"

ALL_IPS_FILE = os.path.join(IPS_DIR, "all_ips.txt")
ALLOWED_IPS_FILE = os.path.join(IPS_DIR, "allowed_ips.txt")
BLOCKED_IPS_FILE = os.path.join(IPS_DIR, "blocked_ips.txt")
UNREACHABLE_IPS_FILE = os.path.join(IPS_DIR, "unreachable_ips.txt")

ALL_IPS_WITH_COUNTRY_FILE = os.path.join(IPS_WITH_COUNTRY_DIR, "all_ips_with_country.txt")
ALLOWED_IPS_WITH_COUNTRY_FILE = os.path.join(IPS_WITH_COUNTRY_DIR, "allowed_ips_with_country.txt")
BLOCKED_IPS_WITH_COUNTRY_FILE = os.path.join(IPS_WITH_COUNTRY_DIR, "blocked_ips_with_country.txt")
UNREACHABLE_IPS_WITH_COUNTRY_FILE = os.path.join(IPS_WITH_COUNTRY_DIR, "unreachable_ips_with_country.txt")

PROXY_IP_FILE = "proxyip.txt"
PROXY_IP_WITH_COUNTRY_FILE = "proxyip_with_country.txt"

REQUIRED_RESULT_COLUMNS = ("IP Address", "Download Speed (MB/s)")


# =========================
# 通用工具
# =========================
def ensure_parent_dir(file_path):
    directory = os.path.dirname(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def clean_config_line(line):
    return line.split("#", 1)[0].strip()


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ip_sort_key(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version, int(addr)
    except ValueError:
        return 99, ip


def remove_file_if_exists(path):
    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception as e:
        print(f"警告: 删除文件失败 {path}: {e}")


def write_empty_file(path):
    ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8"):
        pass


def count_non_empty_lines(file_path):
    count = 0
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


# =========================
# 国家与 IP 数据处理
# =========================
def load_country_mapping(file_path):
    country_mapping = {}

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                parts = line.strip().split(",", 1)
                if len(parts) == 2:
                    code, name = parts
                    country_mapping[code.strip()] = name.strip().replace(" ", "")
    except FileNotFoundError:
        print(f"错误: 文件未找到 {file_path}")
    except Exception as e:
        print(f"错误: 加载国家信息失败: {e}")

    return country_mapping


def load_ip_country_mapping(file_path):
    ip_country = {}

    if not os.path.isfile(file_path):
        return ip_country

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "#" not in line:
                    continue
                ip, info = line.split("#", 1)
                ip = ip.strip()
                info = info.strip()
                if ip and info:
                    ip_country[ip] = info
    except Exception as e:
        print(f"警告: 读取 IP 国家映射失败 {file_path}: {e}")

    return ip_country


def check_tcp_connection(ip, port=TCP_CHECK_PORT, timeout=TCP_CHECK_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def get_country_info(ip, country_mapping, retries=IPINFO_RETRIES, delay=IPINFO_RETRY_DELAY):
    if not check_tcp_connection(ip, port=TCP_CHECK_PORT, timeout=TCP_CHECK_TIMEOUT):
        return "不可达"

    for attempt in range(retries):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=IPINFO_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                code = data.get("country", "未知")
                name = country_mapping.get(code, "未知")
                return f"{code}{name}"

            return "未知"
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(delay)

    return "未知"


def collect_all_ips(manual_ip_file, domains_file, output_file):
    all_ips = set()
    manual_count = 0
    domain_ip_count = 0

    if os.path.exists(manual_ip_file):
        with open(manual_ip_file, "r", encoding="utf-8") as f:
            for line in f:
                ip = clean_config_line(line)
                if not ip:
                    continue

                if is_valid_ip(ip):
                    if ip not in all_ips:
                        manual_count += 1
                    all_ips.add(ip)
                else:
                    print(f"警告: 跳过无效IP {ip}")

    if os.path.exists(domains_file):
        with open(domains_file, "r", encoding="utf-8") as f:
            domains = [clean_config_line(line) for line in f]
            domains = [domain for domain in domains if domain]

        for domain in domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = DNS_TIMEOUT
                resolver.lifetime = DNS_LIFETIME
                results = resolver.resolve(domain, "A")

                for ip in results:
                    if ip.address not in all_ips:
                        domain_ip_count += 1
                    all_ips.add(ip.address)
            except Exception as e:
                print(f"警告: 域名解析失败 {domain}: {e}")

    ensure_parent_dir(output_file)
    with open(output_file, "w", encoding="utf-8") as f:
        for ip in sorted(all_ips, key=ip_sort_key):
            f.write(f"{ip}#未检测\n")

    print(f"已采集 IP: 手动 {manual_count} 个, 域名解析新增 {domain_ip_count} 个, 合计 {len(all_ips)} 个")


def detect_all_ip_country(input_file, output_file, country_mapping):
    ip_info = {}
    total = 0
    updated = 0
    unreachable = 0

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "#" not in line:
                continue

            ip, info = line.split("#", 1)
            ip = ip.strip()
            info = info.strip()

            if ip:
                ip_info[ip] = info

    total = len(ip_info)

    for ip, info in ip_info.items():
        if info == "未检测":
            country = get_country_info(ip, country_mapping)
            ip_info[ip] = country
            updated += 1
            if country == "不可达":
                unreachable += 1

    ensure_parent_dir(output_file)
    with open(output_file, "w", encoding="utf-8") as f:
        for ip, info in sorted(ip_info.items(), key=lambda item: (item[1], ip_sort_key(item[0]))):
            f.write(f"{ip}#{info}\n")

    print(f"国家检测完成: 总计 {total} 个, 本次检测 {updated} 个, 不可达 {unreachable} 个")


def extract_ips_from_file(input_file, output_file):
    try:
        ips = set()

        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if "#" not in line:
                    continue

                ip = line.split("#", 1)[0].strip()
                if ip:
                    ips.add(ip)

        ensure_parent_dir(output_file)
        with open(output_file, "w", encoding="utf-8") as file:
            for ip in sorted(ips, key=ip_sort_key):
                file.write(f"{ip}\n")

        print(f"已输出全部 IP 列表: {len(ips)} 个 -> {output_file}")
    except FileNotFoundError:
        print(f"错误: 文件未找到 {input_file}")
    except Exception as e:
        print(f"错误: 提取 IP 失败: {e}")


def filter_ips_by_allowed_countries(
    input_file,
    allowed_countries_file,
    allowed_ip_file,
    blocked_ip_file,
    allowed_with_info_file,
    blocked_with_info_file,
    unreachable_ip_file,
    unreachable_with_info_file
):
    try:
        allowed = set()

        with open(allowed_countries_file, "r", encoding="utf-8") as f:
            for line in f:
                country = clean_config_line(line).replace(" ", "")
                if country:
                    allowed.add(country)

        allowed_ips = []
        blocked_ips = []
        allowed_info = []
        blocked_info = []
        unreachable_ips = []
        unreachable_info = []

        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if "#" not in line:
                    continue

                ip, info = line.split("#", 1)
                ip = ip.strip()
                info = info.strip()

                if not ip:
                    continue

                line_with_info = f"{ip}#{info}"

                if info in allowed:
                    allowed_ips.append(ip)
                    allowed_info.append(line_with_info)
                elif info == "不可达":
                    blocked_ips.append(ip)
                    blocked_info.append(line_with_info)
                    unreachable_ips.append(ip)
                    unreachable_info.append(line_with_info)
                else:
                    blocked_ips.append(ip)
                    blocked_info.append(line_with_info)

        def info_sort_key(item):
            ip, info = item.split("#", 1)
            return info, ip_sort_key(ip)

        output_tasks = [
            (allowed_ip_file, sorted(allowed_ips, key=ip_sort_key)),
            (blocked_ip_file, sorted(blocked_ips, key=ip_sort_key)),
            (allowed_with_info_file, sorted(allowed_info, key=info_sort_key)),
            (blocked_with_info_file, sorted(blocked_info, key=info_sort_key)),
            (unreachable_ip_file, sorted(unreachable_ips, key=ip_sort_key)),
            (unreachable_with_info_file, sorted(unreachable_info, key=info_sort_key)),
        ]

        for path, data in output_tasks:
            ensure_parent_dir(path)
            with open(path, "w", encoding="utf-8") as f:
                for item in data:
                    f.write(f"{item}\n")

        print(
            f"国家筛选完成: 允许 {len(allowed_ips)} 个, "
            f"拦截 {len(blocked_ips)} 个, 不可达 {len(unreachable_ips)} 个"
        )

    except FileNotFoundError as e:
        print(f"错误: 文件缺失 {e}")
    except Exception as e:
        print(f"错误: 国家筛选失败: {e}")


def save_ip_txt_for_cloudflarescanner(allowed_ip_file, target_path):
    try:
        ensure_parent_dir(target_path)

        if not os.path.isfile(allowed_ip_file):
            print(f"警告: 未找到 {allowed_ip_file}，将创建空文件")
            write_empty_file(target_path)
            return

        with open(allowed_ip_file, "r", encoding="utf-8") as fr:
            lines = fr.readlines()

        with open(target_path, "w", encoding="utf-8") as fw:
            for line in lines:
                fw.write(line)

        print(f"已生成 CloudflareScanner 输入文件: {target_path}")
    except Exception as e:
        print(f"错误: 保存 {target_path} 失败: {e}")


# =========================
# CloudflareScanner 处理
# =========================
def run_cloudflarescanner_with_dn():
    scanner_dir = os.path.abspath(SCANNER_DIR)
    exe_path = os.path.abspath(SCANNER_EXE_PATH)
    ip_txt_path = os.path.abspath(SCANNER_IP_FILE)
    result_csv_path = os.path.abspath(SCANNER_RESULT_CSV)

    if not os.path.isdir(scanner_dir):
        print(f"错误: 未找到目录 {scanner_dir}")
        sys.exit(1)

    if not os.path.isfile(exe_path):
        print(f"错误: 未找到 {exe_path}")
        sys.exit(1)

    if not os.path.isfile(ip_txt_path):
        print(f"错误: 未找到 {ip_txt_path}")
        sys.exit(1)

    ip_count = count_non_empty_lines(ip_txt_path)

    if ip_count == 0:
        print("允许测速的 IP 数为 0，跳过 CloudflareScanner")
        return False

    remove_file_if_exists(result_csv_path)

    print(f"开始运行 CloudflareScanner，待测速 IP 数: {ip_count}")

    try:
        subprocess.run(
            [exe_path, "-dn", str(ip_count)],
            cwd=scanner_dir,
            check=True
        )
        print("CloudflareScanner 运行完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"错误: CloudflareScanner 运行失败，退出码: {e.returncode}")
        sys.exit(1)
    except Exception as e:
        print(f"错误: 运行 CloudflareScanner 失败: {e}")
        sys.exit(1)


def wait_for_result_csv(result_csv_path, timeout=RESULT_WAIT_TIMEOUT, interval=RESULT_WAIT_INTERVAL):
    waited = 0

    while waited < timeout:
        if os.path.isfile(result_csv_path):
            print(f"测速结果已生成: {result_csv_path}")
            return True

        time.sleep(interval)
        waited += interval

    print(f"错误: 等待超时，未生成 {result_csv_path}")
    return False


# =========================
# 测速结果处理
# =========================
def process_result_csv(
    input_file=SCANNER_RESULT_CSV,
    proxyip_file=PROXY_IP_FILE,
    with_country_file=PROXY_IP_WITH_COUNTRY_FILE,
    all_ips_with_country_file=ALL_IPS_WITH_COUNTRY_FILE,
    country_mapping=None,
    retries=IPINFO_RETRIES,
    min_download_speed=MIN_DOWNLOAD_SPEED
):
    if not os.path.isfile(input_file):
        print("错误: 未找到 CloudflareScanner/result.csv")
        sys.exit(1)

    if country_mapping is None:
        country_mapping = load_country_mapping(COUNTRIES_FILE)

    existing_ip_country = load_ip_country_mapping(all_ips_with_country_file)
    valid_infos = []

    with open(input_file, "r", encoding="utf-8-sig", newline="") as csvfile:
        first_line = csvfile.readline()
        csvfile.seek(0)

        delimiter = "\t" if "\t" in first_line else ","
        reader = csv.DictReader(csvfile, delimiter=delimiter)

        fieldnames = reader.fieldnames or []
        missing_columns = [col for col in REQUIRED_RESULT_COLUMNS if col not in fieldnames]

        if missing_columns:
            print(f"错误: result.csv 缺少必要列: {', '.join(missing_columns)}")
            print(f"当前列: {', '.join(fieldnames)}")
            sys.exit(1)

        for row in reader:
            try:
                speed = float((row.get("Download Speed (MB/s)") or "0").strip())
                if speed > min_download_speed:
                    ip = (row.get("IP Address") or "").strip()
                    if ip:
                        valid_infos.append({
                            "ip": ip,
                            "speed": speed
                        })
            except Exception as e:
                print(f"警告: 解析测速结果行失败: {e}")

    valid_infos.sort(key=lambda item: item["speed"], reverse=True)

    ensure_parent_dir(proxyip_file)
    with open(proxyip_file, "w", encoding="utf-8") as outfile:
        for info in valid_infos:
            outfile.write(info["ip"] + "\n")

    print(f"高速 IP 筛选完成: {len(valid_infos)} 个 (> {min_download_speed:g} MB/s)")

    def get_country_code_from_ipinfo(ip):
        for attempt in range(retries):
            try:
                resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=IPINFO_TIMEOUT)
                data = resp.json()
                if "country" in data:
                    return data["country"]
            except Exception:
                pass

            if attempt < retries - 1:
                time.sleep(IPINFO_RETRY_DELAY)

        return "Unknown"

    ensure_parent_dir(with_country_file)
    with open(with_country_file, "w", encoding="utf-8") as outfile:
        for info in valid_infos:
            ip = info["ip"]
            speed = info["speed"]

            country_info = existing_ip_country.get(ip)
            if not country_info or country_info in ("未知", "不可达"):
                country_code = get_country_code_from_ipinfo(ip)
                country_name = country_mapping.get(country_code, "")
                country_info = f"{country_code}{country_name}"

            line = f"{ip}#{speed:.2f}(MB/s){country_info}\n"
            outfile.write(line)

    print(f"结果文件已输出: {proxyip_file}, {with_country_file}")


# =========================
# 主流程
# =========================
if __name__ == "__main__":
    os.makedirs(IPS_WITH_COUNTRY_DIR, exist_ok=True)
    os.makedirs(IPS_DIR, exist_ok=True)

    country_mapping = load_country_mapping(COUNTRIES_FILE)
    if not country_mapping:
        print("错误: 未加载到有效国家信息，程序退出")
        sys.exit(1)

    collect_all_ips(
        manual_ip_file=MANUAL_INPUT_IP_FILE,
        domains_file=DOMAINS_FILE,
        output_file=ALL_IPS_WITH_COUNTRY_FILE
    )

    detect_all_ip_country(
        input_file=ALL_IPS_WITH_COUNTRY_FILE,
        output_file=ALL_IPS_WITH_COUNTRY_FILE,
        country_mapping=country_mapping
    )

    extract_ips_from_file(
        input_file=ALL_IPS_WITH_COUNTRY_FILE,
        output_file=ALL_IPS_FILE
    )

    filter_ips_by_allowed_countries(
        input_file=ALL_IPS_WITH_COUNTRY_FILE,
        allowed_countries_file=ALLOWED_COUNTRIES_FILE,
        allowed_ip_file=ALLOWED_IPS_FILE,
        blocked_ip_file=BLOCKED_IPS_FILE,
        allowed_with_info_file=ALLOWED_IPS_WITH_COUNTRY_FILE,
        blocked_with_info_file=BLOCKED_IPS_WITH_COUNTRY_FILE,
        unreachable_ip_file=UNREACHABLE_IPS_FILE,
        unreachable_with_info_file=UNREACHABLE_IPS_WITH_COUNTRY_FILE,
    )

    save_ip_txt_for_cloudflarescanner(
        allowed_ip_file=ALLOWED_IPS_FILE,
        target_path=SCANNER_IP_FILE
    )

    scanner_ran = run_cloudflarescanner_with_dn()

    if not scanner_ran:
        write_empty_file(PROXY_IP_FILE)
        write_empty_file(PROXY_IP_WITH_COUNTRY_FILE)
        print("未执行测速，已生成空结果文件")
        sys.exit(0)

    if not wait_for_result_csv(SCANNER_RESULT_CSV):
        sys.exit(1)

    process_result_csv(
        input_file=SCANNER_RESULT_CSV,
        proxyip_file=PROXY_IP_FILE,
        with_country_file=PROXY_IP_WITH_COUNTRY_FILE,
        all_ips_with_country_file=ALL_IPS_WITH_COUNTRY_FILE,
        country_mapping=country_mapping,
        retries=IPINFO_RETRIES
    )

    try:
        os.remove(SCANNER_RESULT_CSV)
        print("已清理 CloudflareScanner/result.csv")
    except Exception as e:
        print(f"警告: 删除测速结果文件失败: {e}")