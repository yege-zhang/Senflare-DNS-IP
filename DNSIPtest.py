"""
DNS IP Test - Cloudflare优选域名解析器 v2.1.0
高效解析、检测和识别Cloudflare优选域名的IP状态和详情信息

主要功能:
- DNS解析：多DNS服务器并发解析域名获取IP地址
- 快速筛选：TCP连接测试剔除明显不可用的IP
- 延迟测试：TCP Ping测试获取准确延迟数据
- 带宽测试：HTTP下载测试测量IP带宽性能
- 地区识别：API查询IP地理位置信息并缓存
- 智能排序：综合延迟、带宽、稳定性进行评分排序
- 文件输出：生成基础版和高级版IP列表文件

技术特性:
- 智能缓存系统：支持TTL机制，减少重复API调用
- 并发处理：多线程并发大幅提升检测速度
- 错误处理：完善的异常处理和重试机制
- 日志系统：详细的操作日志记录，支持文件输出
- 资源管理：自动限制缓存大小，防止内存溢出
- 环境优化：针对GitHub Actions等CI环境优化
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
from collections import defaultdict

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
        # 公共DNS服务器（返回国内优化IP，延迟较低）
        '223.5.5.5': '阿里云-DNS',      # 阿里云DNS
        '223.6.6.6': '阿里云-DNS',      # 阿里云DNS
        '180.76.76.76': '百度-DNS',     # 百度DNS
        '119.29.29.29': '腾讯-DNS',     # 腾讯云DNS
        '182.254.116.116': '腾讯-DNS',  # 腾讯云DNS
        '114.114.114.114': '114-DNS',   # 114DNS
        '114.114.115.115': '114-DNS',   # 114DNS

        # 运营商DNS服务器

        # 中国电信DNS（暂时注释，服务器不可用）
        # '218.2.2.2': '中国电信-DNS',
        # '218.4.4.4': '中国电信-DNS',

        # 中国移动DNS（暂时注释，服务器不可用）
        # '211.138.180.2': '中国移动-DNS',
        # '211.138.180.3': '中国移动-DNS',

        # 中国联通DNS
        '123.123.123.123': '中国联通-DNS',  # 联通DNS
        '123.123.123.124': '中国联通-DNS',  # 联通DNS
    },
    # 网络测试配置
    "test_ports": [443],            # TCP连接测试端口（HTTPS端口）
    "timeout": 15,                  # DNS解析超时时间（秒）
    "api_timeout": 5,               # API查询超时时间（秒）
    "query_interval": 0.2,          # API查询间隔时间（秒）

    # 并发处理配置（GitHub Actions环境优化）
    "max_workers": 15,              # 最大并发线程数
    "batch_size": 10,               # 批量处理IP数量
    "cache_ttl_hours": 168,         # 缓存有效期（7天）
    
    # 高级功能配置
    "advanced_mode": True,          # 高级模式开关（True=开启，False=关闭）
    "tcp_ping_count": 5,            # TCP Ping测试次数
    "bandwidth_test_count": 3,       # 带宽测试次数
    "bandwidth_test_size_mb": 1,     # 带宽测试文件大小（MB）
    "latency_filter_percentage": 30, # 延迟排名前百分比（取前30%的IP）
}

# ===== 国家/地区映射表 =====
# ISO国家代码到中文名称的映射，用于地区识别结果显示
COUNTRY_MAPPING = {
    # 北美洲
    'US': '美国', 'CA': '加拿大', 'MX': '墨西哥',
    # 南美洲
    'BR': '巴西', 'AR': '阿根廷', 'CL': '智利',
    # 欧洲
    'UK': '英国', 'GB': '英国', 'FR': '法国', 'DE': '德国', 'IT': '意大利', 'ES': '西班牙', 'NL': '荷兰',
    'RU': '俄罗斯', 'SE': '瑞典', 'CH': '瑞士', 'BE': '比利时', 'AT': '奥地利',
    # 亚洲
    'CN': '中国', 'HK': '中国香港', 'TW': '中国台湾', 'JP': '日本', 'KR': '韩国',
    'SG': '新加坡', 'IN': '印度', 'ID': '印度尼西亚', 'MY': '马来西亚', 'TH': '泰国',
    # 大洋洲
    'AU': '澳大利亚', 'NZ': '新西兰',
    # 非洲
    'ZA': '南非', 'EG': '埃及', 'NG': '尼日利亚',
    # 未知地区
    'Unknown': '未知'
}

# ===== 全局变量 =====
region_cache = {}  # IP地区信息缓存，减少重复API调用

# ===== 网络会话配置 =====
# 创建HTTP会话，配置请求头和连接池以提高性能
session = requests.Session()
# 设置浏览器请求头，模拟真实浏览器访问
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
# 配置HTTP连接池，提高并发请求性能
adapter = requests.adapters.HTTPAdapter(
    pool_connections=10,    # 连接池数量
    pool_maxsize=20,        # 每个连接池最大连接数
    max_retries=3          # 最大重试次数
)
session.mount('http://', adapter)
session.mount('https://', adapter)

# ===== 1. 缓存管理模块 =====
# 智能缓存系统，支持TTL机制，减少重复API调用，提高程序运行效率

def load_region_cache():
    """加载地区缓存文件到内存"""
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
    """保存地区缓存到文件"""
    try:
        with open('Cache.json', 'w', encoding='utf-8') as f:
            json.dump(region_cache, f, ensure_ascii=False)
        logger.info(f"💾 成功保存缓存文件，包含 {len(region_cache)} 个条目")
    except Exception as e:
        logger.error(f"❌ 保存缓存文件失败: {str(e)[:50]}")
        pass

def is_cache_valid(timestamp, ttl_hours=24):
    """检查缓存是否在有效期内"""
    if not timestamp:
        return False
    cache_time = datetime.fromisoformat(timestamp)
    return datetime.now() - cache_time < timedelta(hours=ttl_hours)

def clean_expired_cache():
    """清理过期缓存条目并限制缓存大小，防止内存溢出"""
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

# ===== 2. 文件操作模块 =====
# 文件管理功能，包括删除、加载、保存等操作

def delete_file_if_exists(file_path):
    """删除指定文件（如果存在），避免结果累积"""
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"🗑️ 已删除原有文件: {file_path}")
        except Exception as e:
            logger.warning(f"⚠️ 删除文件失败: {str(e)}")

def load_domain_list():
    """从YXhost-lite.txt文件加载域名列表，支持注释行过滤"""
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

# ===== 3. DNS解析模块 =====
# 多DNS服务器并发解析，获取最优IP地址

def resolve_domain(domain):
    """使用多个DNS服务器解析域名获取IP地址，支持重试机制"""
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
                if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip) and all(0 <= int(part) <= 255 for part in ip.split('.')):
                    server_ips.append(ip)
                    all_ips.append(ip)
            
            if server_ips:
                successful_servers.append((dns_server, dns_provider))
                unique_count = len(set(all_ips))
                logger.info(f"🔍 [{i:2d}/{len(CONFIG['dns_servers'])}] {domain} -> {len(server_ips)} 个IP ({dns_provider}: {dns_server}) | 累计唯一IP: {unique_count}")
                logger.info(f"📋 {dns_provider}({dns_server}) 解析到的IP: {', '.join(server_ips)}")
            else:
                failed_servers.append((dns_server, dns_provider))
                logger.debug(f"❌ [{i:2d}/{len(CONFIG['dns_servers'])}] DNS服务器 {dns_server} 未返回有效IP")
                
        except Exception as e:
            failed_servers.append((dns_server, dns_provider))
            logger.debug(f"❌ [{i:2d}/{len(CONFIG['dns_servers'])}] DNS服务器 {dns_server} 解析 {domain} 失败: {str(e)[:50]}")
            
            # 失败重试一次（仅对关键DNS服务器）
            if dns_server in ['223.5.5.5', '223.6.6.6', '119.29.29.29']:  # 只重试主要DNS服务器
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
                        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip) and all(0 <= int(part) <= 255 for part in ip.split('.')):
                            server_ips.append(ip)
                            all_ips.append(ip)
                    
                    if server_ips:
                        successful_servers.append((dns_server, dns_provider))
                        failed_servers.remove((dns_server, dns_provider))  # 从失败列表中移除
                        unique_count = len(set(all_ips))
                        logger.info(f"✅ 重试成功 [{i:2d}/{len(CONFIG['dns_servers'])}] {domain} -> {len(server_ips)} 个IP ({dns_provider}: {dns_server}) | 累计唯一IP: {unique_count}")
                        logger.info(f"📋 {dns_provider}({dns_server}) 重试解析到的IP: {', '.join(server_ips)}")
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

# ===== 4. 网络检测模块 =====
# IP可用性检测、延迟测试、带宽测试等功能

def quick_filter_ip(ip):
    """快速筛选IP，单次TCP连接测试，剔除明显不可用的IP"""
    # 验证IP地址格式
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return False
    except (ValueError, AttributeError):
        return False
    
    # 检查测试端口配置
    if not CONFIG["test_ports"] or not isinstance(CONFIG["test_ports"], list):
        return False
    
    min_delay = float('inf')
    
    # 遍历配置的测试端口，只测试一次
    for port in CONFIG["test_ports"]:
        try:
            # 验证端口号
            if not isinstance(port, int) or not (1 <= port <= 65535):
                continue
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)  # 3秒超时
                start_time = time.time()
                
                # 尝试TCP连接
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start_time) * 1000)
                    min_delay = min(min_delay, delay)
                    
                    # 如果延迟很好，立即返回
                    if delay < 200:
                        return (True, delay)
        except (socket.timeout, socket.error, OSError):
            continue  # 继续测试下一个端口
        except Exception as e:
            logger.debug(f"IP {ip} 端口 {port} 快速筛选异常: {str(e)[:30]}")
            continue
    
    # 如果延迟超过500ms，直接剔除
    if min_delay > 500:
        return (False, 0)
    
    # 如果无法连接，直接剔除
    if min_delay == float('inf'):
        return (False, 0)
    
    return (True, min_delay)

def test_ip_availability(ip, ping_count=None):
    """TCP Socket检测IP可用性，多次ping测试获取准确延迟数据"""
    if ping_count is None:
        ping_count = CONFIG["tcp_ping_count"]
    # 验证IP地址格式
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0, 0, 0)
    except (ValueError, AttributeError):
        return (False, 0, 0, 0)
    
    # 检查测试端口配置
    if not CONFIG["test_ports"] or not isinstance(CONFIG["test_ports"], list):
        logger.warning(f"⚠️ 测试端口配置无效，跳过IP {ip}")
        return (False, 0, 0, 0)
    
    all_delays = []
    success_count = 0
    
    # 多次ping测试
    for ping_attempt in range(ping_count):
        min_delay = float('inf')
        
        # 遍历配置的测试端口
        for port in CONFIG["test_ports"]:
            try:
                # 验证端口号
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    continue
                    
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)  # 3秒超时
                    start_time = time.time()
                    
                    # 尝试TCP连接
                    if s.connect_ex((ip, port)) == 0:
                        delay = round((time.time() - start_time) * 1000)
                        min_delay = min(min_delay, delay)
                        
                        # 如果延迟很好，记录并继续
                        if delay < 200:
                            all_delays.append(delay)
                            success_count += 1
                            break  # 找到好的延迟就跳出端口循环
            except (socket.timeout, socket.error, OSError):
                continue  # 继续测试下一个端口
            except Exception as e:
                logger.debug(f"IP {ip} 端口 {port} 检测异常: {str(e)[:30]}")
                continue
        
        # 如果这次ping没有成功，记录一个高延迟值
        if min_delay == float('inf'):
            all_delays.append(999)  # 标记为失败
        else:
            all_delays.append(min_delay)
    
    # 计算统计结果
    if success_count > 0:
        # 过滤掉失败的值（999）
        valid_delays = [d for d in all_delays if d < 999]
        if valid_delays:
            min_delay = min(valid_delays)
            avg_delay = sum(valid_delays) / len(valid_delays)
            # 计算稳定性（方差）
            variance = sum((d - avg_delay) ** 2 for d in valid_delays) / len(valid_delays)
            stability = round(variance, 2)
            return (True, min_delay, avg_delay, stability)
    
    return (False, 0, 0, 0)

def test_ip_bandwidth(ip, test_size_mb=None):
    """通过HTTP下载测试IP带宽性能"""
    if test_size_mb is None:
        test_size_mb = CONFIG["bandwidth_test_size_mb"]
    try:
        import requests
        
        # 验证IP地址格式
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts):
            return (False, 0, 0)
        
        # 使用真实的下载测试来测量带宽
        test_size_bytes = test_size_mb * 1024 * 1024
        test_urls = [
            # 使用一些公开的测试文件
            f"https://speed.cloudflare.com/__down?bytes={test_size_bytes}",  # 可配置大小测试文件
            f"https://httpbin.org/bytes/{test_size_bytes}",  # 可配置大小测试文件
        ]
        
        best_speed = 0
        best_latency = 0
        
        # 使用配置的测试次数
        test_count = CONFIG["bandwidth_test_count"]
        for test_attempt in range(test_count):
            for url in test_urls:
                try:
                    start_time = time.time()
                    
                    # 发送HTTP请求测试带宽
                    response = requests.get(
                        url, 
                        timeout=15,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                        stream=True
                    )
                    
                    if response.status_code == 200:
                        # 测量下载速度
                        data_size = 0
                        start_download = time.time()
                        
                        # 下载数据块来测试速度
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                data_size += len(chunk)
                                # 限制测试时间，避免过长时间
                                if time.time() - start_download > 10:  # 最多测试10秒
                                    break
                                # 如果下载了足够的数据就停止
                                if data_size > 10 * 1024 * 1024:  # 10MB
                                    break
                        
                        download_time = time.time() - start_download
                        latency = (start_download - start_time) * 1000  # 延迟
                        
                        if download_time > 0 and data_size > 0:
                            # 计算速度 (Mbps)
                            speed_mbps = (data_size * 8) / (download_time * 1000000)
                            best_speed = max(best_speed, speed_mbps)
                            best_latency = latency if best_latency == 0 else min(best_latency, latency)
                            
                            # 如果速度很好，可以提前返回
                            if speed_mbps > 5:  # 超过5Mbps就认为很好
                                return (True, best_speed, best_latency)
                
                except Exception as e:
                    logger.debug(f"IP {ip} 带宽测试失败: {str(e)[:50]}")
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

def calculate_score(min_delay, avg_delay, bandwidth, stability):
    """计算IP综合评分，综合考虑延迟、带宽、稳定性"""
    # 延迟评分 (0-100, 延迟越低分数越高)
    latency_score = max(0, 100 - avg_delay / 2)
    
    # 带宽评分 (0-100, 带宽越高分数越高)
    bandwidth_score = min(100, bandwidth * 10)
    
    # 稳定性评分 (0-100, 稳定性越高分数越高)
    stability_score = max(0, 100 - stability / 10)
    
    # 综合评分 (延迟占40%, 带宽占30%, 稳定性占30%)
    total_score = latency_score * 0.4 + bandwidth_score * 0.3 + stability_score * 0.3
    return round(total_score, 1)

def test_ip_bandwidth_only(ip, index, total):
    """仅测试IP带宽，用于分离测试流程"""
    # 测试带宽
    is_fast, bandwidth, latency = test_ip_bandwidth(ip)
    
    # 输出带宽测试日志
    logger.info(f"⚡ [{index}/{total}] {ip}（带宽综合速度：{bandwidth:.2f}Mbps）")
    
    return (is_fast, bandwidth, latency)

def latency_filter_ips(ips_with_latency):
    """按延迟排名筛选前百分比IP，保留最优IP"""
    if not CONFIG["advanced_mode"] or not ips_with_latency:
        return ips_with_latency
    
    # 按延迟排序
    sorted_ips = sorted(ips_with_latency, key=lambda x: x[2])  # 按avg_delay排序
    
    # 计算前百分比的数量
    percentage = CONFIG["latency_filter_percentage"]
    keep_count = max(1, int(len(sorted_ips) * percentage / 100))
    
    # 取前N个IP
    filtered_ips = sorted_ips[:keep_count]
    
    logger.info(f"🔍 延迟排名前{percentage}%筛选：从 {len(ips_with_latency)} 个IP中筛选出 {len(filtered_ips)} 个IP")
    
    # 显示筛选结果
    for i, (ip, min_delay, avg_delay, stability) in enumerate(filtered_ips, 1):
        logger.info(f"📊 {ip}（延迟排名第{i}位：{avg_delay:.1f}ms）")
    
    return filtered_ips

# ===== 5. 地区识别模块 =====
# IP地理位置识别，支持多API和智能缓存

def get_ip_region(ip):
    """识别IP地理位置，支持缓存TTL机制和多API备用"""
    # 检查缓存是否有效
    if ip in region_cache:
        cached_data = region_cache[ip]
        if isinstance(cached_data, dict) and 'timestamp' in cached_data:
            if is_cache_valid(cached_data['timestamp'], CONFIG["cache_ttl_hours"]):
                # 缓存命中，记录缓存来源（延迟输出）
                # 不立即输出，由调用方统一控制日志顺序
                return cached_data['region']
        else:
            # 兼容旧格式缓存
            return cached_data
    
    # 尝试主要API（免费版本）
    logger.info(f"🌐 IP {ip} 开始API查询（主要API: ipinfo.io lite）...")
    try:
        resp = session.get(f'https://api.ipinfo.io/lite/{ip}?token=2cb674df499388', timeout=CONFIG["api_timeout"])
        if resp.status_code == 200:
            data = resp.json()
            country_code = data.get('country_code', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 主要API识别成功: {country_code}（来源：API查询）")
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
            data = resp.json()
            country_code = data.get('countryCode', '').upper()
            if country_code:
                region_cache[ip] = {
                    'region': country_code,
                    'timestamp': datetime.now().isoformat()
                }
                logger.info(f"✅ IP {ip} 备用API识别成功: {country_code}（来源：备用API查询）")
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
    """根据ISO国家代码获取中文名称"""
    return COUNTRY_MAPPING.get(code, code)

# ===== 6. 并发处理模块 =====
# 多线程并发处理，大幅提升检测效率

def quick_filter_ips(ips, max_workers=None):
    """并发快速筛选IP，剔除明显不可用的IP"""
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"🔍 开始快速筛选 {len(ips)} 个IP，剔除明显不好的IP...")
    filtered_ips = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(quick_filter_ip, ip): ip for ip in ips}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                if isinstance(result, tuple):
                    is_good, current_delay = result
                    if is_good:
                        filtered_ips.append(ip)
                        logger.info(f"✅ 可用 {ip}（延迟 {current_delay}ms）")
                    else:
                        logger.info(f"❌ {ip} 被快速筛选剔除")
            except Exception as e:
                logger.error(f"❌ {ip} 快速筛选出错: {str(e)[:30]}")
    
    elapsed = time.time() - start_time
    logger.info(f"🔍 快速筛选完成，从 {len(ips)} 个IP中筛选出 {len(filtered_ips)} 个IP，耗时: {elapsed:.1f}秒")
    return filtered_ips

def test_ips_concurrently(ips, max_workers=None):
    """并发检测IP可用性，TCP Ping测试获取延迟数据"""
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"📡 开始并发检测 {len(ips)} 个IP，使用 {max_workers} 个线程，测试类型: 延迟")
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
            future_to_ip = {executor.submit(test_ip_availability, ip): ip for ip in batch_ips}
            
            # 处理完成的任务
            batch_completed = 0
            timeout = 30  # TCP测试超时时间
            for future in as_completed(future_to_ip, timeout=timeout):
                ip = future_to_ip[future]
                batch_completed += 1
                completed = i + batch_completed
                elapsed = time.time() - start_time
                
                try:
                    is_available, min_delay, avg_delay, stability = future.result()
                    if is_available:
                        available_ips.append((ip, min_delay, avg_delay, stability))
                        logger.info(f"🎯 [{completed}/{len(ips)}] {ip}（TCP Ping 综合延迟：{avg_delay:.1f}ms）")
                    else:
                        logger.info(f"[{completed}/{len(ips)}] {ip} ❌ 不可用")
                    
                except Exception as e:
                    logger.error(f"[{completed}/{len(ips)}] {ip} ❌ 检测出错: {str(e)[:30]} - 耗时: {elapsed:.1f}s")
                    
        
        # 批次间短暂休息，避免过度占用资源
        if i + batch_size < len(ips):
            time.sleep(0.1)  # 减少休息时间
    
    total_time = time.time() - start_time
    logger.info(f"📡 并发检测完成，发现 {len(available_ips)} 个可用IP，总耗时: {total_time:.1f}秒")
    
    
    return available_ips

def get_regions_concurrently(ips, max_workers=None):
    """并发识别IP地理位置，保持日志输出顺序"""
    if max_workers is None:
        max_workers = CONFIG["max_workers"]
    
    logger.info(f"🌍 开始并发地区识别 {len(ips)} 个IP，使用 {max_workers} 个线程")
    results = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_ip = {executor.submit(get_ip_region, ip): (ip, min_delay, avg_delay) for ip, min_delay, avg_delay in ips}
        
        # 先收集所有结果，不输出日志
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
                    
                    # 只在API查询时等待，缓存查询不需要等待
                    if i % 10 == 0:  # 每10个IP等待一次，减少等待频率
                        time.sleep(CONFIG["query_interval"])
                except Exception as e:
                    logger.warning(f"地区识别失败 {ip}: {str(e)[:50]}")
                    results.append((ip, 'Unknown', min_delay, avg_delay))
        
        # 所有结果收集完成后，先输出缓存获取日志，再输出地区识别结果
        for i, (ip, region_code, min_delay, avg_delay) in enumerate(results, 1):
            # 检查是否从缓存获取
            if ip in region_cache:
                cached_data = region_cache[ip]
                if isinstance(cached_data, dict) and 'timestamp' in cached_data:
                    if is_cache_valid(cached_data['timestamp'], CONFIG["cache_ttl_hours"]):
                        logger.info(f"📦 IP {ip} 地区信息从缓存获取: {cached_data['region']}")
            logger.info(f"📦 [{i}/{len(ips)}] {ip} -> {region_code}")
                    
    
    total_time = time.time() - start_time
    logger.info(f"🌍 地区识别完成，处理了 {len(results)} 个IP，总耗时: {total_time:.1f}秒")
    return results

# ===== 7. 主程序模块 =====
# 程序主流程控制，协调各个模块完成完整的IP检测流程

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
            
            # 使用DNS解析
            ips = resolve_domain(domain)
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
    logger.info(f"🔢 去重前共 {len(all_ips)} 个IP地址")
    unique_ips = sorted(list(set(all_ips)), key=lambda x: [int(p) for p in x.split('.')])
    logger.info(f"🔢 去重后共 {len(unique_ips)} 个唯一IP地址")
    
    # 检查是否有重复IP
    if len(all_ips) != len(unique_ips):
        logger.info(f"🔍 发现重复IP，已去重 {len(all_ips) - len(unique_ips)} 个重复项")
    
    # 检查是否有IP需要检测
    if not unique_ips:
        logger.warning("⚠️ 没有解析到任何IP地址，程序结束")
        return

    # 5. 快速筛选IP（剔除明显不好的）
    logger.info("🔍 ===== 快速筛选IP =====")
    filtered_ips = quick_filter_ips(unique_ips)
    
    if not filtered_ips:
        logger.warning("⚠️ 快速筛选后没有可用IP，程序结束")
        return
    
    # 6. 立即保存基础文件（快速筛选完成后）
    logger.info("📄 ===== 保存基础文件 =====")
    with open('DNSIPlist.txt', 'w', encoding='utf-8') as f:
        for ip in filtered_ips:
            f.write(f"{ip}\n")
    logger.info(f"📄 已保存 {len(filtered_ips)} 个可用IP到 DNSIPlist.txt")
    
    # 7. 立即进行地区识别与结果格式化（提前保存SenflareDNS.txt）
    logger.info("🌍 ===== 并发地区识别与结果格式化 =====")
    # 使用快速筛选的IP进行地区识别
    ip_delay_data = [(ip, 0, 0) for ip in filtered_ips]  # 使用快速筛选的IP，延迟设为0
    
    region_results = get_regions_concurrently(ip_delay_data)
    
    # 按地区分组
    region_groups = defaultdict(list)
    for ip, region_code, min_delay, avg_delay in region_results:
        country_name = get_country_name(region_code)
        region_groups[country_name].append((ip, region_code, min_delay, avg_delay))
    
    logger.info(f"🌍 地区分组完成，共 {len(region_groups)} 个地区")
    
    # 生成并保存最终结果
    result = []
    for region in sorted(region_groups.keys()):
        # 同一地区内按延迟排序（更快的在前）
        sorted_ips = sorted(region_groups[region], key=lambda x: x[2])  # 按min_delay排序
        for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
            result.append(f"{ip}#{code} {region}节点 | {idx:02d}")
        logger.debug(f"地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
    
    if result:
        # 立即保存基础文件
        with open('SenflareDNS.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(result))
        logger.info(f"📄 已保存 {len(result)} 条格式化记录到 SenflareDNS.txt")
    else:
        logger.warning("⚠️ 无有效记录可保存")
    
    # 高级功能处理（仅当开启高级模式时）
    if CONFIG["advanced_mode"]:
        # 8. 延迟排名前30%筛选（基于快速筛选结果）
        logger.info("🔍 ===== 延迟排名前30%筛选 =====")
        # 对快速筛选的IP进行延迟排名筛选，使用快速筛选的实际延迟数据
        quick_filter_results = []
        for ip in filtered_ips:
            # 重新获取快速筛选的延迟数据
            is_good, delay = quick_filter_ip(ip)
            if is_good:
                quick_filter_results.append((ip, delay, delay, 0))  # (ip, min_delay, avg_delay, stability)
        
        latency_filtered_ips = latency_filter_ips(quick_filter_results)
        
        # 9. TCP Ping测试（只测试延迟，不测试带宽）
        logger.info("🔍 ===== TCP Ping测试 =====")
        tcp_ping_ips = test_ips_concurrently([ip for ip, _, _, _ in latency_filtered_ips])
        
        
        # 10. 带宽测试（只对筛选后的IP进行带宽测试）
        logger.info("🔍 ===== 带宽测试 =====")
        # 进行带宽测试
        bandwidth_results = []
        for i, (ip, _, _, _) in enumerate(tcp_ping_ips, 1):
            is_fast, bandwidth, latency = test_ip_bandwidth_only(ip, i, len(tcp_ping_ips))
            if is_fast:
                # 找到对应的延迟数据
                for orig_ip, min_delay, avg_delay, stability in tcp_ping_ips:
                    if orig_ip == ip:
                        score = calculate_score(min_delay, avg_delay, bandwidth, stability)
                        bandwidth_results.append((ip, min_delay, avg_delay, bandwidth, latency, score))
                        break
        
        available_ips = bandwidth_results
        
        # 11. 保存高级文件（按评分排序）
        if available_ips:
            # 按评分排序（如果测试了带宽）
            if len(available_ips[0]) > 5:
                available_ips.sort(key=lambda x: x[5], reverse=True)  # 按评分排序
                logger.info(f"📊 按综合评分排序完成")
                
                # 保存高级文件（高级选项）
                # 保存优选IP
                with open('DNSIPlist-Pro.txt', 'w', encoding='utf-8') as f:
                    for ip, min_delay, avg_delay, bandwidth, latency, score in available_ips:
                        f.write(f"{ip}\n")
                logger.info(f"📄 已保存 {len(available_ips)} 个优选IP到 DNSIPlist-Pro.txt")
                
                # 保存排名详情
                with open('Ranking.txt', 'w', encoding='utf-8') as f:
                    for i, (ip, min_delay, avg_delay, bandwidth, latency, score) in enumerate(available_ips, 1):
                        f.write(f"📊 [{i}/{len(available_ips)}] {ip}（延迟 {min_delay}ms，带宽 {bandwidth:.2f}Mbps，评分 {score:.1f}）\n")
                logger.info(f"📄 已保存排名详情到 Ranking.txt")
                
                # 保存高级格式化文件（使用优选IP重新生成）
                logger.info("🌍 ===== 高级地区识别与结果格式化 =====")
                # 使用优选IP进行地区识别
                pro_ip_delay_data = [(ip, 0, 0) for ip, _, _, _, _, _ in available_ips]
                
                pro_region_results = get_regions_concurrently(pro_ip_delay_data)
                
                # 按地区分组
                pro_region_groups = defaultdict(list)
                for ip, region_code, min_delay, avg_delay in pro_region_results:
                    country_name = get_country_name(region_code)
                    pro_region_groups[country_name].append((ip, region_code, min_delay, avg_delay))
                
                logger.info(f"🌍 高级地区分组完成，共 {len(pro_region_groups)} 个地区")
                
                # 生成高级格式化结果
                pro_result = []
                for region in sorted(pro_region_groups.keys()):
                    # 同一地区内按延迟排序（更快的在前）
                    sorted_ips = sorted(pro_region_groups[region], key=lambda x: x[2])  # 按min_delay排序
                    for idx, (ip, code, min_delay, avg_delay) in enumerate(sorted_ips, 1):
                        pro_result.append(f"{ip}#{code} {region}节点 | {idx:02d}")
                    logger.debug(f"高级地区 {region} 格式化完成，包含 {len(sorted_ips)} 个IP")
                
                if pro_result:
                    with open('SenflareDNS-Pro.txt', 'w', encoding='utf-8') as f:
                        f.write('\n'.join(pro_result))
                    logger.info(f"📄 已保存 {len(pro_result)} 条高级格式化记录到 SenflareDNS-Pro.txt")
                else:
                    logger.warning("⚠️ 高级版无有效记录可保存")
    
    # 12. 保存缓存并显示统计信息
    save_region_cache()
    
    # 显示总耗时
    run_time = round(time.time() - start_time, 2)
    logger.info(f"⏱️ 总耗时: {run_time}秒")
    logger.info(f"📊 缓存统计: 总计 {len(region_cache)} 个")
    logger.info("🏁 ===== 程序完成 =====")

# ===== 8. 程序入口 =====
# 程序启动入口，初始化缓存并执行主程序
if __name__ == "__main__":
    # 程序启动日志
    logger.info("🚀 ===== 开始DNS IP处理程序 =====")
    # 初始化缓存系统
    load_region_cache()
    # 清理过期缓存条目
    clean_expired_cache()
    # 执行主程序流程
    try:
        main()
    except KeyboardInterrupt:
        logger.info("⏹️ 程序被用户中断")
    except Exception as e:
        logger.error(f"❌ 程序运行出错: {str(e)}")
