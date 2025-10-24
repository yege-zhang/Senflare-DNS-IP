"""
DNS IP Test - Cloudflare优选域名解析器 v1.0.0
高效解析、检测和识别Cloudflare优选域名的IP状态和详情信息

主要特性:
- 智能缓存系统，支持TTL机制
- 并发处理，大幅提升检测速度
- 多源IP获取：DNS解析 + HTTP请求解析
- 完善日志，所有操作都有Emoji记录
- 错误处理，特别优化DNS解析错误
- 自动限制缓存大小，防止文件过大
- GitHub Actions环境优化
"""

# ===== 标准库导入 =====
import re
import os
import time
import socket
import json
import logging
import dns.resolver
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter

# ===== 第三方库导入 =====
import requests
from urllib3.exceptions import InsecureRequestWarning

# ===== 配置和初始化 =====

# 禁用SSL证书警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('DNSIPtest.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ===== 核心配置 =====
CONFIG = {
    # DNS服务器配置 - 中国大陆DNS服务器（获取大陆延迟最低的IP）
    "dns_servers": {
        # 公共DNS（返回国内优化IP）
        '223.5.5.5': '阿里云-DNS',
        '223.6.6.6': '阿里云-DNS',
        '180.76.76.76': '百度-DNS',
        '119.29.29.29': '腾讯-DNS',
        '182.254.116.116': '腾讯-DNS',
        '114.114.114.114': '114-DNS',
        '114.114.115.115': '114-DNS',
        '101.226.4.6': '360-DNS',
        '218.30.118.6': '360-DNS',
        '123.125.81.6': '搜狗-DNS',
        '140.207.198.6': '搜狗-DNS',
        
        # 运营商DNS（返回运营商优化IP，延迟最低）
        # 中国电信（暂时注释，DNS服务器不可用）
        # '218.2.2.2': '中国电信-DNS',
        # '218.4.4.4': '中国电信-DNS',
        
        # 中国移动（暂时注释，DNS服务器不可用）
        # '211.138.180.2': '中国移动-DNS',
        # '211.138.180.3': '中国移动-DNS',
        
        # 中国联通
        '123.123.123.123': '中国联通-DNS',
        '123.123.123.124': '中国联通-DNS',
    },
    
    # 脚本参数配置
    "test_ports": [443],            # 测试核心端口
    "timeout": 15,                  # DNS解析超时时间（增加到15秒）
    "api_timeout": 5,               # API查询超时时间
    "query_interval": 0.2,          # API查询间隔（增加到0.2秒）
    
    
    # 并发处理配置（GitHub Actions环境优化）
    "max_workers": 15,              # 最大并发线程数（减少以适应GitHub Actions）
    "batch_size": 8,                # 批量处理大小（减少以适应GitHub Actions）
    "cache_ttl_hours": 168,         # 缓存TTL（7天）
}

# ===== 国家/地区映射表（简化版）=====
COUNTRY_MAPPING = {
    # 主要国家和地区
    'US': '美国', 'CA': '加拿大', 'MX': '墨西哥',
    'BR': '巴西', 'AR': '阿根廷', 'CL': '智利',
    'UK': '英国', 'GB': '英国', 'FR': '法国', 'DE': '德国', 'IT': '意大利', 'ES': '西班牙', 'NL': '荷兰',
    'RU': '俄罗斯', 'SE': '瑞典', 'CH': '瑞士', 'BE': '比利时', 'AT': '奥地利',
    'CN': '中国', 'HK': '中国香港', 'TW': '中国台湾', 'JP': '日本', 'KR': '韩国',
    'SG': '新加坡', 'IN': '印度', 'ID': '印度尼西亚', 'MY': '马来西亚', 'TH': '泰国',
    'AU': '澳大利亚', 'NZ': '新西兰',
    'ZA': '南非', 'EG': '埃及', 'NG': '尼日利亚',
    'Unknown': '未知'
}

# ===== 全局变量 =====
region_cache = {}

# ===== 网络会话配置 =====
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Cache-Control': 'max-age=0'
})

# 配置连接池
adapter = requests.adapters.HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=3
)
session.mount('http://', adapter)
session.mount('https://', adapter)

# ===== 缓存管理模块 =====

def load_region_cache():
    """加载地区缓存"""
    global region_cache
    if os.path.exists('Cache.json'):
        try:
            with open('Cache.json', 'r', encoding='utf-8') as f:
                region_cache = json.load(f)
            logger.info(f"📦 成功加载缓存文件，包含 {len(region_cache)} 个条目")
        except Exception as e:
            logger.warning(f"⚠️ 加载缓存文件失败: {str(e)[:50]}")
            region_cache = {}
    else:
        logger.info("📦 缓存文件不存在，使用空缓存")
        region_cache = {}

def save_region_cache():
    """保存地区缓存"""
    try:
        with open('Cache.json', 'w', encoding='utf-8') as f:
            json.dump(region_cache, f, ensure_ascii=False)
        logger.info(f"💾 成功保存缓存文件，包含 {len(region_cache)} 个条目")
    except Exception as e:
        logger.error(f"❌ 保存缓存文件失败: {str(e)[:50]}")
        pass

def is_cache_valid(timestamp, ttl_hours=24):
    """检查缓存是否有效"""
    if not timestamp:
        return False
    cache_time = datetime.fromisoformat(timestamp)
    return datetime.now() - cache_time < timedelta(hours=ttl_hours)

def clean_expired_cache():
    """清理过期缓存和限制缓存大小"""
    global region_cache
    current_time = datetime.now()
    expired_keys = []
    
    # 清理过期缓存
    for ip, data in region_cache.items():
        if isinstance(data, dict) and 'timestamp' in data:
            cache_time = datetime.fromisoformat(data['timestamp'])
            if current_time - cache_time >= timedelta(hours=CONFIG["cache_ttl_hours"]):
                expired_keys.append(ip)
    
    for key in expired_keys:
        del region_cache[key]
    
    # 限制缓存大小（最多保留1000个条目）
    if len(region_cache) > 1000:
        # 按时间排序，删除最旧的条目
        sorted_items = sorted(region_cache.items(), 
                            key=lambda x: x[1].get('timestamp', '') if isinstance(x[1], dict) else '')
        items_to_remove = len(region_cache) - 1000
        for i in range(items_to_remove):
            del region_cache[sorted_items[i][0]]
        logger.info(f"缓存过大，清理了 {items_to_remove} 个旧条目")
    
    if expired_keys:
        logger.info(f"清理了 {len(expired_keys)} 个过期缓存条目")

# ===== 文件操作模块 =====

def delete_file_if_exists(file_path):
    """删除原有文件，避免结果累积"""
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"🗑️ 已删除原有文件: {file_path}")
        except Exception as e:
            logger.warning(f"⚠️ 删除文件失败: {str(e)}")

def load_domain_list():
    """从YXhost-lite.txt加载域名列表"""
    domains = []
    if os.path.exists('YXhost-lite.txt'):
        try:
            with open('YXhost-lite.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 提取域名部分，忽略#后面的描述信息
                        domain = line.split('#')[0].strip()
                        if domain:
                            domains.append(domain)
            logger.info(f"📄 成功加载 {len(domains)} 个域名")
        except Exception as e:
            logger.error(f"❌ 加载域名文件失败: {str(e)}")
    else:
        logger.warning("⚠️ YXhost-lite.txt 文件不存在")
    return domains

# ===== DNS解析模块 =====

def resolve_domain(domain):
    """解析域名获取IP地址 - 优化版本"""
    all_ips = []
    successful_servers = []
    failed_servers = []
    
    logger.info(f"🔍 开始解析域名 {domain}，使用 {len(CONFIG['dns_servers'])} 个DNS服务器...")
    
    # 尝试多个DNS服务器
    for i, (dns_server, dns_provider) in enumerate(CONFIG["dns_servers"].items(), 1):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = 5  # 减少超时时间到5秒
            resolver.lifetime = 5
            
            # 查询A记录
            answers = resolver.resolve(domain, 'A')
            server_ips = []
            for answer in answers:
                ip = str(answer)
                # 验证IP地址格式
                if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                    if all(0 <= int(part) <= 255 for part in ip.split('.')):
                        server_ips.append(ip)
                        all_ips.append(ip)
            
            if server_ips:
                successful_servers.append((dns_server, dns_provider))
                unique_count = len(set(all_ips))
                logger.info(f"🔍 [{i:2d}/{len(CONFIG['dns_servers'])}] {domain} -> {len(server_ips)} 个IP ({dns_provider}: {dns_server}) | 累计唯一IP: {unique_count}")
                logger.info(f"📋 解析到的IP列表: {', '.join(server_ips)}")
            else:
                failed_servers.append((dns_server, dns_provider))
                logger.debug(f"❌ [{i:2d}/{len(CONFIG['dns_servers'])}] DNS服务器 {dns_server} 未返回有效IP")
                
        except Exception as e:
            failed_servers.append((dns_server, dns_provider))
            logger.debug(f"❌ [{i:2d}/{len(CONFIG['dns_servers'])}] DNS服务器 {dns_server} 解析 {domain} 失败: {str(e)[:50]}")
            
            # 失败重试一次
            try:
                logger.info(f"🔄 重试DNS服务器 {dns_server}...")
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3  # 重试时使用更短的超时时间
                resolver.lifetime = 3
                
                answers = resolver.resolve(domain, 'A')
                server_ips = []
                for answer in answers:
                    ip = str(answer)
                    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                        if all(0 <= int(part) <= 255 for part in ip.split('.')):
                            server_ips.append(ip)
                            all_ips.append(ip)
                
                if server_ips:
                    successful_servers.append((dns_server, dns_provider))
                    failed_servers.remove((dns_server, dns_provider))  # 从失败列表中移除
                    unique_count = len(set(all_ips))
                    logger.info(f"✅ 重试成功 [{i:2d}/{len(CONFIG['dns_servers'])}] {domain} -> {len(server_ips)} 个IP ({dns_provider}: {dns_server}) | 累计唯一IP: {unique_count}")
                    logger.info(f"📋 解析到的IP列表: {', '.join(server_ips)}")
                else:
                    logger.debug(f"❌ 重试失败 [{i:2d}/{len(CONFIG['dns_servers'])}] DNS服务器 {dns_server} 重试后仍无有效IP")
                    
            except Exception as retry_e:
                logger.debug(f"❌ 重试失败 [{i:2d}/{len(CONFIG['dns_servers'])}] DNS服务器 {dns_server} 重试失败: {str(retry_e)[:50]}")
            continue
    
    unique_ips = list(set(all_ips))  # 去重
    logger.info(f"📊 {domain} 解析完成: 成功 {len(successful_servers)} 个DNS服务器，失败 {len(failed_servers)} 个，获得 {len(unique_ips)} 个唯一IP")
    
    # 显示成功的DNS服务器
    if successful_servers:
        logger.info(f"✅ 成功的DNS服务器: {', '.join([f'{provider}({server})' for server, provider in successful_servers])}")
    
    # 显示失败的DNS服务器
    if failed_servers:
        logger.info(f"❌ 失败的DNS服务器: {', '.join([f'{provider}({server})' for server, provider in failed_servers])}")
    
    # 显示所有解析到的IP
    if unique_ips:
        logger.info(f"📋 解析到的IP列表: {', '.join(unique_ips)}")
    
    return unique_ips


def resolve_domain_multiple_methods(domain):
    """使用DNS解析域名获取IP地址"""
    all_ips = []
    
    # DNS解析
    logger.info(f"🔍 DNS解析 {domain}")
    dns_ips = resolve_domain(domain)
    all_ips.extend(dns_ips)
    logger.info(f"📊 DNS解析获得 {len(dns_ips)} 个IP")
    
    # 去重并统计
    unique_ips = list(set(all_ips))
    logger.info(f"📊 {domain} DNS解析完成: 总计 {len(unique_ips)} 个唯一IP")
    
    if unique_ips:
        logger.info(f"📋 所有解析到的IP列表: {', '.join(unique_ips)}")
    
    return unique_ips

# ===== 网络检测模块 =====

def test_ip_availability(ip):
    """TCP Socket检测IP可用性 - 优化版本"""
    # 验证IP地址格式
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0, 0)
    except (ValueError, AttributeError):
        return (False, 0, 0)
    
    # 检查测试端口配置
    if not CONFIG["test_ports"] or not isinstance(CONFIG["test_ports"], list):
        logger.warning(f"⚠️ 测试端口配置无效，跳过IP {ip}")
        return (False, 0, 0)
    
    min_delay = float('inf')
    success_count = 0
    total_delay = 0
    
    # 遍历配置的测试端口
    for port in CONFIG["test_ports"]:
        try:
            # 验证端口号
            if not isinstance(port, int) or not (1 <= port <= 65535):
                logger.warning(f"⚠️ 无效端口号 {port}，跳过")
                continue
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)  # 3秒超时
                start_time = time.time()
                
                # 尝试TCP连接
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start_time) * 1000)
                    min_delay = min(min_delay, delay)
                    total_delay += delay
                    success_count += 1
                    
                    # 如果延迟很好，立即返回最佳结果
                    if delay < 200:
                        return (True, delay, delay)
        except (socket.timeout, socket.error, OSError):
            continue  # 继续测试下一个端口
        except Exception as e:
            logger.debug(f"IP {ip} 端口 {port} 检测异常: {str(e)[:30]}")
            continue
    
    # 返回最佳结果
    if success_count > 0:
        avg_delay = total_delay / success_count
        return (True, min_delay, avg_delay)
    
    return (False, 0, 0)


def test_ip_bandwidth(ip, test_size_mb=1):
    """测试IP带宽 - 通过TCP连接速度测试"""
    try:
        # 验证IP地址格式
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0, 0)
        
        # 测试多个端口来模拟带宽测试
        test_ports = [80, 443, 8080, 8443]
        best_speed = 0
        best_latency = 0
        
        for port in test_ports:
            try:
                start_time = time.time()
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    
                    # 尝试连接
                    if s.connect_ex((ip, port)) == 0:
                        connect_time = time.time() - start_time
                        latency = connect_time * 1000
                        
                        # 模拟数据传输测试
                        try:
                            # 发送一些数据来测试传输速度
                            test_data = b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n'
                            s.send(test_data)
                            
                            # 尝试接收响应
                            response = s.recv(1024)
                            if response:
                                # 计算传输速度（基于连接时间和数据传输）
                                # 这里使用连接时间作为速度的参考指标
                                speed_mbps = (len(test_data) + len(response)) * 8 / (connect_time * 1000000)
                                best_speed = max(best_speed, speed_mbps)
                                best_latency = latency if best_latency == 0 else min(best_latency, latency)
                                
                                logger.info(f"📊 {ip}:{port} 连接测试: 延迟 {latency:.1f}ms")
                                
                        except Exception as e:
                            logger.debug(f"IP {ip}:{port} 数据传输测试失败: {str(e)[:30]}")
                            continue
                    
            except Exception as e:
                logger.debug(f"IP {ip}:{port} 连接测试失败: {str(e)[:30]}")
                continue
        
        if best_speed > 0:
            return (True, best_speed, best_latency)
        else:
            # 如果带宽测试失败，返回延迟测试结果
            is_available, latency = test_ip_availability(ip)
            if is_available:
                return (True, 0, latency)  # 返回0表示带宽测试失败，但延迟可用
            else:
                return (False, 0, 0)
            
    except Exception as e:
        logger.error(f"IP {ip} 带宽测试异常: {str(e)[:50]}")
        return (False, 0, 0)


def test_ip_comprehensive(ip):
    """综合测试IP - 延迟 + 带宽"""
    # 先测试延迟
    is_available, min_delay, avg_delay = test_ip_availability(ip)
    
    if not is_available:
        return (False, 0, 0, 0, 0)
    
    # 再测试带宽
    is_fast, bandwidth, latency = test_ip_bandwidth(ip)
    
    return (True, min_delay, avg_delay, bandwidth, latency)


# ===== 地区识别模块 =====

def get_ip_region(ip):
    """优化的IP地区识别（支持缓存TTL）"""
    # 检查缓存是否有效
    if ip in region_cache:
        cached_data = region_cache[ip]
        if isinstance(cached_data, dict) and 'timestamp' in cached_data:
            if is_cache_valid(cached_data['timestamp'], CONFIG["cache_ttl_hours"]):
                logger.info(f"📦 IP {ip} 地区信息从缓存获取: {cached_data['region']}")
                return cached_data['region']
        else:
            # 兼容旧格式缓存
            logger.info(f"📦 IP {ip} 地区信息从缓存获取（旧格式）: {cached_data}")
            return cached_data
    
    # 尝试主要API
    logger.info(f"🌐 IP {ip} 开始API查询（主要API: ipinfo.io）...")
    try:
        resp = session.get(f'https://ipinfo.io/{ip}?token=2cb674df499388', timeout=CONFIG["api_timeout"])
        if resp.status_code == 200:
            country_code = resp.json().get('country', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 主要API识别成功: {country_code}")
                return country_code
        else:
            logger.warning(f"⚠️ IP {ip} 主要API返回状态码: {resp.status_code}")
    except Exception as e:
        logger.error(f"❌ IP {ip} 主要API识别失败: {str(e)[:30]}")
        pass
    
    # 尝试备用API
    logger.info(f"🌐 IP {ip} 尝试备用API（ip-api.com）...")
    try:
        resp = session.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=CONFIG["api_timeout"])
        if resp.json().get('status') == 'success':
            country_code = resp.json().get('countryCode', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 备用API识别成功: {country_code}")
                return country_code
        else:
            logger.warning(f"⚠️ IP {ip} 备用API返回状态: {resp.json().get('status', 'unknown')}")
    except Exception as e:
        logger.error(f"❌ IP {ip} 备用API识别失败: {str(e)[:30]}")
        pass
    
    # 失败返回Unknown
    logger.warning(f"❌ IP {ip} 所有API识别失败，标记为Unknown")
    region_cache[ip] = {
        'region': 'Unknown',
        'timestamp': datetime.now().isoformat()
    }
    return 'Unknown'

def get_country_name(code):
    """根据国家代码获取中文名称"""
    return COUNTRY_MAPPING.get(code, code)

# ===== 并发处理模块 =====

def test_ips_concurrently(ips, max_workers=None, test_bandwidth=False):
    """超快并发检测IP可用性 - 优化版本"""
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    test_type = "延迟+带宽" if test_bandwidth else "延迟"
    logger.info(f"📡 开始并发检测 {len(ips)} 个IP，使用 {max_workers} 个线程，测试类型: {test_type}")
    available_ips = []
    
    # 使用更小的批次，避免卡住
    batch_size = CONFIG["batch_size"]
    start_time = time.time()
    
    for i in range(0, len(ips), batch_size):
        batch_ips = ips[i:i+batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(ips)-1)//batch_size + 1
        
        logger.info(f"📡 处理批次 {batch_num}/{total_batches}，包含 {len(batch_ips)} 个IP")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交批次任务，添加超时保护
            if test_bandwidth:
                future_to_ip = {executor.submit(test_ip_comprehensive, ip): ip for ip in batch_ips}
            else:
                future_to_ip = {executor.submit(test_ip_availability, ip): ip for ip in batch_ips}
            
            # 处理完成的任务
            batch_completed = 0
            timeout = 60 if test_bandwidth else 30  # 带宽测试需要更长时间
            for future in as_completed(future_to_ip, timeout=timeout):
                ip = future_to_ip[future]
                batch_completed += 1
                completed = i + batch_completed
                elapsed = time.time() - start_time
                
                try:
                    if test_bandwidth:
                        is_available, min_delay, avg_delay, bandwidth, latency = future.result()
                        if is_available:
                            available_ips.append((ip, min_delay, avg_delay, bandwidth, latency))
                            logger.info(f"[{completed}/{len(ips)}] {ip} ✅ 可用（延迟 {min_delay}ms，带宽 {bandwidth:.2f}Mbps）- 耗时: {elapsed:.1f}s")
                        else:
                            logger.info(f"[{completed}/{len(ips)}] {ip} ❌ 不可用 - 耗时: {elapsed:.1f}s")
                    else:
                        is_available, min_delay, avg_delay = future.result()
                        if is_available:
                            available_ips.append((ip, min_delay, avg_delay))
                            logger.info(f"[{completed}/{len(ips)}] {ip} ✅ 可用（延迟 {min_delay}ms，平均 {avg_delay:.1f}ms）- 耗时: {elapsed:.1f}s")
                        else:
                            logger.info(f"[{completed}/{len(ips)}] {ip} ❌ 不可用 - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
                except Exception as e:
                    logger.error(f"[{completed}/{len(ips)}] {ip} ❌ 检测出错: {str(e)[:30]} - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
        
        # 批次间短暂休息，避免过度占用资源
        if i + batch_size < len(ips):
            time.sleep(0.2)  # 减少休息时间
    
    total_time = time.time() - start_time
    logger.info(f"📡 并发检测完成，发现 {len(available_ips)} 个可用IP，总耗时: {total_time:.1f}秒")
    return available_ips

def get_regions_concurrently(ips, max_workers=None):
    """优化的并发地区识别 - 保持日志顺序"""
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"🌍 开始并发地区识别 {len(ips)} 个IP，使用 {max_workers} 个线程")
    results = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_ip = {executor.submit(get_ip_region, ip): (ip, min_delay, avg_delay) for ip, min_delay, avg_delay in ips}
        
        # 按提交顺序处理结果，保持日志顺序
        for i, (ip, min_delay, avg_delay) in enumerate(ips, 1):
            future = None
            # 找到对应的future
            for f, (f_ip, f_min_delay, f_avg_delay) in future_to_ip.items():
                if f_ip == ip and f_min_delay == min_delay and f_avg_delay == avg_delay:
                    future = f
                    break
            
            if future:
                try:
                    region_code = future.result()
                    results.append((ip, region_code, min_delay, avg_delay))
                    country_name = get_country_name(region_code)
                    elapsed = time.time() - start_time
                    logger.info(f"[{i}/{len(ips)}] {ip} -> {country_name} ({region_code}) - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
                    
                    # 只在API查询时等待，缓存查询不需要等待
                    if i % 5 == 0:  # 每5个IP等待一次，减少等待频率
                        time.sleep(CONFIG["query_interval"])
                except Exception as e:
                    logger.warning(f"地区识别失败 {ip}: {str(e)[:50]}")
                    results.append((ip, 'Unknown', min_delay, avg_delay))
                    elapsed = time.time() - start_time
                    logger.info(f"[{i}/{len(ips)}] {ip} -> 未知 (Unknown) - 耗时: {elapsed:.1f}s")
                    
                    # 添加小延迟确保日志顺序
                    time.sleep(0.01)  # 10ms延迟
    
    total_time = time.time() - start_time
    logger.info(f"🌍 地区识别完成，处理了 {len(results)} 个IP，总耗时: {total_time:.1f}秒")
    return results

# ===== 主程序模块 =====

def main():
    start_time = time.time()
    
    # 1. 预处理：删除旧文件
    delete_file_if_exists('DNSIPlist.txt')
    delete_file_if_exists('SenflareDNS.txt')
    logger.info("🗑️ 预处理完成，旧文件已清理")

    # 2. 加载域名列表
    logger.info("📥 ===== 加载域名列表 =====")
    domains = load_domain_list()
    
    if not domains:
        logger.warning("⚠️ 没有找到任何域名，程序结束")
        return
    
    # 3. 多方法解析获取IP地址
    logger.info("🔍 ===== 多方法解析域名 =====")
    all_ips = []
    successful_domains = 0
    failed_domains = 0
    
    for i, domain in enumerate(domains):
        try:
            logger.info(f"🔍 解析域名 {domain}...")
            # 添加请求间隔，避免频率限制
            if i > 0:
                time.sleep(CONFIG["query_interval"])
            
            # 使用多方法解析（DNS + HTTP）
            ips = resolve_domain_multiple_methods(domain)
            if ips:
                all_ips.extend(ips)
                successful_domains += 1
                logger.info(f"✅ 成功解析 {domain}，获得 {len(ips)} 个IP地址")
            else:
                failed_domains += 1
                logger.warning(f"❌ 解析 {domain} 失败，未获得IP地址")
        except Exception as e:
            failed_domains += 1
            error_msg = str(e)[:50]
            logger.error(f"❌ 解析 {domain} 出错: {error_msg}")
    
    logger.info(f"📊 解析统计: 成功 {successful_domains} 个域名，失败 {failed_domains} 个域名")

    # 4. IP去重与排序
    unique_ips = sorted(list(set(all_ips)), key=lambda x: [int(p) for p in x.split('.')])
    logger.info(f"🔢 去重后共 {len(unique_ips)} 个唯一IP地址")
    
    # 检查是否有IP需要检测
    if not unique_ips:
        logger.warning("⚠️ 没有解析到任何IP地址，程序结束")
        return

    # 5. 并发检测IP可用性
    logger.info("📡 ===== 并发检测IP可用性 =====")
    # 可以选择是否测试带宽（默认只测试延迟）
    test_bandwidth = False  # 设置为True来测试带宽
    available_ips = test_ips_concurrently(unique_ips, test_bandwidth=test_bandwidth)
    
    # 6. 保存可用IP列表
    if available_ips:
        with open('DNSIPlist.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join([ip for ip, _, _ in available_ips]))
        logger.info(f"📄 已保存 {len(available_ips)} 个可用IP到 DNSIPlist.txt")
        
        # 7. 并发地区识别与结果格式化
        logger.info("🌍 ===== 并发地区识别与结果格式化 =====")
        region_results = get_regions_concurrently(available_ips)
        
        # 按地区分组
        region_groups = defaultdict(list)
        for ip, region_code, min_delay, avg_delay in region_results:
            country_name = get_country_name(region_code)
            region_groups[country_name].append((ip, region_code, min_delay, avg_delay))
        
        logger.info(f"🌍 地区分组完成，共 {len(region_groups)} 个地区")
        
        # 8. 生成并保存最终结果
        result = []
        for region in sorted(region_groups.keys()):
            # 同一地区内按延迟排序（更快的在前）
            sorted_ips = sorted(region_groups[region], key=lambda x: x[2])  # 按min_delay排序
            for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
                result.append(f"{ip}#{code} {region}节点 | {idx:02d}")
            logger.debug(f"地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
        
        if result:
            with open('SenflareDNS.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(result))
            logger.info(f"📊 已保存 {len(result)} 条格式化记录到 SenflareDNS.txt")
        else:
            logger.warning("⚠️ 无有效记录可保存")
        
        # 9. 保存缓存并显示统计信息
        save_region_cache()
        
        # 显示总耗时
        run_time = round(time.time() - start_time, 2)
        logger.info(f"⏱️ 总耗时: {run_time}秒")
        logger.info(f"📊 缓存统计: 总计 {len(region_cache)} 个")
        logger.info("🏁 ===== 程序完成 =====")
    else:
        logger.warning("⚠️ 未检测到可用IP，跳过后续处理")
        return

# ===== 程序入口 =====
if __name__ == "__main__":
    # 程序启动日志
    logger.info("🚀 ===== 开始DNS IP处理程序 =====")
    
    # 初始化缓存
    load_region_cache()
    
    # 清理过期缓存
    clean_expired_cache()
    
    try:
        main()
    except KeyboardInterrupt:
        logger.info("⏹️ 程序被用户中断")
    except Exception as e:
        logger.error(f"❌ 运行出错: {str(e)}")
