import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

import csv
import ipaddress
import os
import socket
import subprocess
import time

import dns.resolver
import requests


MIN_DOWNLOAD_SPEED = 5.0

SCANNER_DIR = "CloudflareScanner"
SCANNER_EXE = "CloudflareScanner.exe"
SCANNER_EXE_PATH = os.path.join(SCANNER_DIR, SCANNER_EXE)
SCANNER_IP_FILE = os.path.join(SCANNER_DIR, "ip.txt")
SCANNER_RESULT_CSV = os.path.join(SCANNER_DIR, "result.csv")

REQUIRED_RESULT_COLUMNS = ("IP Address", "Download Speed (MB/s)")


def ensure_parent_dir(file_path):
    directory = os.path.dirname(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

def clean_config_line(line):
    return line.split('#', 1)[0].strip()


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ip_sort_key(ip):
    try:
        address = ipaddress.ip_address(ip)
        return address.version, int(address)
    except ValueError:
        return 99, ip


def load_country_mapping(file_path):
    country_mapping = {}

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split(',', 1)
                if len(parts) == 2:
                    code, name = parts
                    country_mapping[code.strip()] = name.strip().replace(" ", "")
    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 未找到。")
    except Exception as e:
        print(f"加载国家信息时发生错误: {e}")

    return country_mapping


def check_tcp_connection(ip, port=443, timeout=5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def get_country_info(ip, country_mapping, retries=10, delay=1):
    attempt = 0

    while attempt < retries:
        if not check_tcp_connection(ip, port=443):
            print(f"IP {ip} 无法连接，跳过国家信息查询。")
            return "不可达"

        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                code = data.get("country", "未知")
                name = country_mapping.get(code, "未知")
                print(f"检测到 IP {ip} 的国家: {code}{name}")
                return f"{code}{name}"

            print(f"API响应异常: {response.status_code}")
            return "未知"
        except requests.exceptions.RequestException as e:
            print(f"请求异常: {e}")
            attempt += 1

            if attempt < retries:
                print(f"重试 {attempt}/{retries} 中...")
                time.sleep(delay)
            else:
                print(f"无法获取 {ip} 的国家信息。")
                return "未知"

    return "未知"


def collect_all_ips(manual_ip_file, domains_file, output_file):
    all_ips = set()

    if os.path.exists(manual_ip_file):
        with open(manual_ip_file, 'r', encoding='utf-8') as f:
            for line in f:
                ip = clean_config_line(line)

                if not ip:
                    continue

                if is_valid_ip(ip):
                    all_ips.add(ip)
                else:
                    print(f"跳过无效IP: {ip}")

    if os.path.exists(domains_file):
        with open(domains_file, 'r', encoding='utf-8') as f:
            domains = [clean_config_line(line) for line in f]
            domains = [domain for domain in domains if domain]

        for domain in domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 10
                resolver.lifetime = 15

                print(f"开始检测 {domain}...")
                results = resolver.resolve(domain, 'A')

                for ip in results:
                    all_ips.add(ip.address)
            except Exception as e:
                print(f"域名 {domain} 解析失败: {e}")

    ensure_parent_dir(output_file)

    with open(output_file, 'w', encoding='utf-8') as f:
        for ip in sorted(all_ips, key=ip_sort_key):
            f.write(f"{ip}#未检测\n")

    print(f"所有采集的IP已保存到 {output_file}")


def detect_all_ip_country(input_file, output_file, country_mapping):
    ip_info = {}

    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            if '#' not in line:
                continue

            ip, info = line.split('#', 1)
            ip = ip.strip()
            info = info.strip()

            if ip:
                ip_info[ip] = info

    for ip, info in ip_info.items():
        if info == "未检测":
            country = get_country_info(ip, country_mapping)
            ip_info[ip] = country

    ensure_parent_dir(output_file)

    with open(output_file, 'w', encoding='utf-8') as f:
        for ip, info in sorted(ip_info.items(), key=lambda item: (item[1], ip_sort_key(item[0]))):
            f.write(f"{ip}#{info}\n")

    print(f"所有IP归属地检测完成，已更新到 {output_file}")


def extract_ips_from_file(input_file, output_file):
    try:
        ips = set()

        with open(input_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()

                if '#' not in line:
                    continue

                ip = line.split('#', 1)[0].strip()

                if ip:
                    ips.add(ip)

        ensure_parent_dir(output_file)

        with open(output_file, 'w', encoding='utf-8') as file:
            for ip in sorted(ips, key=ip_sort_key):
                file.write(f"{ip}\n")

        print(f"提取的IP已保存到 {output_file}")
    except FileNotFoundError:
        print(f"文件未找到: {input_file}")
    except Exception as e:
        print(f"提取出错: {e}")


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

        with open(allowed_countries_file, 'r', encoding='utf-8') as f:
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

        with open(input_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()

                if '#' not in line:
                    continue

                ip, info = line.split('#', 1)
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
            ip, info = item.split('#', 1)
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

            with open(path, 'w', encoding='utf-8') as f:
                for item in data:
                    f.write(f"{item}\n")

        print("筛选完成：")
        print(f"✅ 允许: {len(allowed_ips)} 个IP → {allowed_ip_file}, {allowed_with_info_file}")
        print(f"❌ 拦截: {len(blocked_ips)} 个IP → {blocked_ip_file}, {blocked_with_info_file}")
        print(f"🚫 不可达: {len(unreachable_ips)} 个IP → {unreachable_ip_file}, {unreachable_with_info_file}")

    except FileNotFoundError as e:
        print(f"文件缺失: {e}")
    except Exception as e:
        print(f"筛选时发生错误: {e}")


def save_ip_txt_for_cloudflarescanner(allowed_ip_file, target_path):
    try:
        ensure_parent_dir(target_path)

        if not os.path.isfile(allowed_ip_file):
            print(f"未找到 {allowed_ip_file}，创建空的 {target_path}")

            with open(target_path, 'w', encoding='utf-8'):
                pass

            return

        with open(allowed_ip_file, 'r', encoding='utf-8') as fr:
            lines = fr.readlines()

        with open(target_path, 'w', encoding='utf-8') as fw:
            for line in lines:
                fw.write(line)

        print(f"已保存 {target_path}")
    except Exception as e:
        print(f"保存 {target_path} 时发生错误: {e}")


def remove_file_if_exists(path):
    try:
        if os.path.isfile(path):
            os.remove(path)
            print(f"已删除旧文件 {path}")
    except Exception as e:
        print(f"删除旧文件 {path} 时发生错误: {e}")


def write_empty_file(path):
    ensure_parent_dir(path)

    with open(path, 'w', encoding='utf-8'):
        pass

    print(f"已生成空文件 {path}")


def count_non_empty_lines(file_path):
    count = 0

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                count += 1

    return count


def run_cloudflarescanner_with_dn():
    if not os.path.isfile(SCANNER_EXE_PATH):
        print(f"未找到 {SCANNER_EXE_PATH}")
        sys.exit(1)

    if not os.path.isfile(SCANNER_IP_FILE):
        print(f"未找到 {SCANNER_IP_FILE}")
        sys.exit(1)

    ip_count = count_non_empty_lines(SCANNER_IP_FILE)

    if ip_count == 0:
        print(f"{SCANNER_IP_FILE}        SV)

    try:
        subprocess.run(
            [".\\CloudflareScanner.exe", "-dn", str(ip_count)],
            cwd=SCANNER_DIR,
            check=True
        )

        print(f"已运行 CloudflareScanner.exe -dn {ip_count}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"运行 {SCANNER_EXE_PATH} 失败，退出码: {e.returncode}")
        sys.exit(1)
    except Exception as e:
        print(f"运行 {SCANNER_EXE_PATH} 时发生错误: {e}")
        sys.exit(1)


def wait_for_result_csv(result_csv_path, timeout=600, interval=2):
    print(f"等待 {result_csv_path} 文件生成 ...")

    waited = 0

    while waited < timeout:
        if os.path.isfile(result_csv_path):
            print(f"{result_csv_path} 已生成，继续执行后续任务。")
            return True

        time.sleep(interval)
        waited += interval

    print(f"等待超时：{result_csv_path} 仍未生成。")
    return False


def load_result_country_dict(countries_file):
    country_dict = {}

    with open(countries_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(',', 1)

            if len(parts) >= 2:
                code = parts[0].strip()
                name = parts[1].strip().replace(" ", "")
                country_dict[code] = name

    return country_dict


def process_result_csv(
    input_file=SCANNER_RESULT_CSV,
    proxyip_file='proxyip.txt',
    with_country_file='proxyip_with_country.txt',
    countries_file='countries.txt',
    RETRY=10,
    min_download_speed=MIN_DOWNLOAD_SPEED
):
    if not os.path.isfile(input_file):
        print('未找到 CloudflareScanner/result.csv，请确认 CloudflareScanner.exe 已成功运行并生成此文件。')
        sys.exit(1)

    country_dict = load_result_country_dict(countries_file)
    valid_infos = []

    with open(input_file, 'r', encoding='utf-8-sig', newline='') as csvfile:
        first_line = csvfile.readline()
        csvfile.seek(0)

        delimiter = '\t' if '\t' in first_line else ','
        reader = csv.DictReader(csvfile, delimiter=delimiter)

        fieldnames = reader.fieldnames or []
        missing_columns = [
            column
            for column in REQUIRED_RESULT_COLUMNS
            if column not in fieldnames
        ]

        if missing_columns:
            print(f"result.csv 缺少必要列: {', '.join(missing_columns)}")
            print(f"当前检测到的列: {', '.join(fieldnames)}")
            sys.exit(1)

        for row in reader:
            try:
                speed = float((row.get('Download Speed (MB/s)') or '0').strip())

                if speed > min_download_speed:
                    ip = (row.get('IP Address') or '').strip()

                    if ip:
                        valid_infos.append({
                            'ip': ip,
                            'speed': speed
                        })
            except Exception as e:
                print(f"Error parsing row: {row}, error: {e}")

    valid_infos.sort(key=lambda item: item['speed'], reverse=True)

    ensure_parent_dir(proxyip_file)

    with open(proxyip_file, 'w', encoding='utf-8') as outfile:
        for info in valid_infos:
            outfile.write(info['ip'] + '\n')

    print(f"筛选完成，共输出 {len(valid_infos)} 个下载速度大于 {min_download_speed:g} MB/s 的IP到 {proxyip_file}")

    def get_country(ip):
        for attempt in range(RETRY):
            try:
                url = f'https://ipinfo.io/{ip}/json'
                resp = requests.get(url, timeout=5)
                data = resp.json()

                if 'country' in data:
                    return data['country']

                print(f"{ip} 未返回国家，响应内容：{data}")
            except Exception as e:
                print(f"第 {attempt + 1} 次获取 {ip} 国家信息失败，错误：{e}")

            time.sleep(1)

        return 'Unknown'

    ensure_parent_dir(with_country_file)

    with open(with_country_file, 'w', encoding='utf-8') as outfile:
        for info in valid_infos:
            ip = info['ip']
            speed = info['speed']
            country_code = get_country(ip)
            country_name = country_dict.get(country_code, "")

            line = f"{ip}#{speed:.2f}(MB/s){country_code}{country_name}\n"
            outfile.write(line)
            print(line.strip())

    print(f"查询国家并格式化输出完成，共输出 {len(valid_infos)} 个IP到 {with_country_file}")


def list_files(prefix=""):
    print(f"{prefix} 当前目录内容:")

    for root, dirs, files in os.walk(".", topdown=True):
        for name in files:
            print("  ", os.path.join(root, name))


if __name__ == "__main__":
    os.makedirs("ips_with_country", exist_ok=True)
    os.makedirs("ips", exist_ok=True)

    country_mapping = load_country_mapping("countries.txt")

    if not country_mapping:
        print("未加载有效国家信息，程序退出。")
        sys.exit(1)

    all_ips_with_country = "ips_with_country/all_ips_with_country.txt"

    collect_all_ips(
        manual_ip_file="Manual_input_IP.txt",
        domains_file="domains.txt",
        output_file=all_ips_with_country
    )

    detect_all_ip_country(
        input_file=all_ips_with_country,
        output_file=all_ips_with_country,
        country_mapping=country_mapping
    )

    extract_ips_from_file(
        input_file=all_ips_with_country,
        output_file="ips/all_ips.txt"
    )

    filter_ips_by_allowed_countries(
        input_file=all_ips_with_country,
        allowed_countries_file="allowed_countries.txt",
        allowed_ip_file="ips/allowed_ips.txt",
        blocked_ip_file="ips/blocked_ips.txt",
        allowed_with_info_file="ips_with_country/allowed_ips_with_country.txt",
        blocked_with_info_file="ips_with_country/blocked_ips_with_country.txt",
        unreachable_ip_file="ips/unreachable_ips.txt",
        unreachable_with_info_file="ips_with_country/unreachable_ips_with_country.txt",
    )

    save_ip_txt_for_cloudflarescanner(
        allowed_ip_file="ips/allowed_ips.txt",
        target_path=SCANNER_IP_FILE
    )

    list_files("运行 exe 前")

    scanner_ran = run_cloudflarescanner_with_dn()

    if not scanner_ran:
        write_empty_file("proxyip.txt")
        write_empty_file("proxyip_with_country.txt")
        sys.exit(0)

    list_files("运行 exe 后")

    if not wait_for_result_csv(SCANNER_RESULT_CSV, timeout=600, interval=2):
        sys.exit(1)

    process_result_csv(
        input_file=SCANNER_RESULT_CSV,
        proxyip_file='proxyip.txt',
        with_country_file='proxyip_with_country.txt',
        countries_file='countries.txt',
        RETRY=10
    )

    try:
        os.remove(SCANNER_RESULT_CSV)
        print(f"已删除 {SCANNER_RESULT_CSV}")
    except Exception as e:
        print(f"删除 {SCANNER_RESULT_CSV} 时发生错误: {e}")