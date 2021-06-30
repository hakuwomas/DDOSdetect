import scapy.all as scapy
from datetime import datetime, timedelta
import netifaces as ni
import csv
import time
from mlp_analyzer import mlp_analyzer
from event_ui import event_ui


class traffic_analyzer:
    def __init__(self, iface_name, train_mode=None):
        """
      

        :param iface_name: Network interface name      
        :param train_mode: Set to list of True and what activity to record when need to collect data (e.g. [True, 'anomaly'])
        """

        if train_mode is None:
            train_mode = [False, ]
            self.__train_path = None
        self.__iface_name = iface_name        
        self.__train_mode = train_mode[0]
        self.__even_logger = event_ui('DDOS')
        if self.__train_mode:
            self.__train_path = train_mode[1]
        self.__ids_ip = ni.ifaddresses('ens38')[ni.AF_INET][0]['addr']

        self.__packet_dict = {}
        self.__session_list_update_value = 1
        self.__query_packet_dict = {}
        self.__response_packet_dict = {}
        self.__analyzed_index = 0    
        self.__ip_dict = {} 
        self.__buff_ip_dict = {}  
        self.__next_time = 0      
        self.__index = 0
        self.__delta = 2
        self.flag = 0

    def __update_session_list(self):
        """
        Updates session list for calculating sessions' length in future
        """
        scapy_pl = scapy.PacketList(self.__packet_dict)           

    
    def __process_packets(self, packet):
        		
        if self.__next_time == 0:
            self.__next_time = time.time() + self.__delta
        
        if time.time() < self.__next_time:
            if (packet.payload.name != 'ARP' and str(packet.payload.src) not in self.__buff_ip_dict):
                self.__buff_ip_dict[str(packet.payload.src)] = 1     
            elif packet.payload.name != 'ARP':
                self.__buff_ip_dict[str(packet.payload.src)] += 1
        else:
            if self.__index >= 5:
                self.__index = 0
                for ip in self.__ip_dict:
                    arr = []
                    if len(self.__ip_dict[ip]) != 5:
                        for i in range(len(self.__ip_dict[ip]) - 1, 4):
                                self.__ip_dict[ip].append(0)                
                    analyzer = mlp_analyzer('mlp_model.sav')
                    arr.append(self.__ip_dict[ip])
                    verdict = analyzer.analyze(arr)
                    self.__even_logger.print_event(verdict, ip)
                self.__next_time = time.time() + self.__delta
                self.__ip_dict = {}
            else:
                self.__index += 1
                
                for ip in self.__buff_ip_dict:
                    arr = []

                    if ip not in self.__ip_dict:                    
                        arr.append(self.__buff_ip_dict[ip])
                        self.__ip_dict[ip] = arr
                    else:
                        arr = self.__ip_dict[ip]
                        arr.append(self.__buff_ip_dict[ip])
                        self.__ip_dict[ip] = arr
            self.__buff_ip_dict = {}
            self.__next_time = time.time() + self.__delta

        if len(self.__packet_dict) % self.__session_list_update_value == 0:
            self.__update_session_list()

    def sniff_packets(self):
              
        scapy.sniff(iface=self.__iface_name,                    
                    session=scapy.TCPSession,
                    store=False,
                    prn=self.__process_packets
                    )
