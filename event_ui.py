import os

class event_ui:
    def __init__(self, name):
        self.__name = name
        self.__block_ip_arr = []
        self.__legal_ip_arr = []
        f = open("block_ip.txt", "r")
        for line in f:
            self.__block_ip_arr.append(line)
        f.close()

        f = open("legal_ip.txt", "r")
        for line in f:
            self.__legal_ip_arr.append(line)
        f.close()


    def print_event(self, verdict, ip):
        if ip in self.__block_ip_arr or ip in self.__legal_ip_arr:
            return                    

        print("""
        DDOS attack captured: 
        Verdict: {verdict}""".format(
                   verdict='normal' if verdict == 1 else 'anomaly'))
        if verdict == -1:        
            command = raw_input('\t\tBlock user ' + ip + ' ?[y/n]')
            if command == 'y':
                self.__block_ip_arr.append(ip)
                f = open("block_ip.txt", "a")
                f.write(ip + "\n")
                f.close()
                os.system('iptables -A INPUT -s ' + ip + ' -j DROP')
                print('\t\tUser has been blocked')
            if command == 'n':
                print('\t\tIgnore')



