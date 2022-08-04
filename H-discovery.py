import scapy.all as scapy
from tqdm import tqdm
import ipaddress as ipaddr

def get_host_list(IP,PREFIX_LENGTH):
    network = ipaddr.IPv4Network(IP +'/'+ PREFIX_LENGTH)
    Hosts_list = [str(ip) for ip in network]
    return Hosts_list   


Hosts_list = get_host_list('192.168.8.0','24')
clients = list()
#Logo and signature                               
print(r""" ||    _                                      _
           ||   //                                     ||
           || //    _____       _____            ___   ||
           ||\\    /  _  \  __ /  _  \ -     -  / _  \ ||
           ||  \\ /  (_|  ||/    (_)$  |     | | (_|  ||||____  
           ||   \\\_______||   \_____/ ||___|| \_____/||  _   \   __
                                                      || |_).  |//__)
                                                  _____|_\_____/||___ .01lig""")
print("\n****************************************************\n")
print("********Copyright of gilles karougbe, jully 2022********")
print("*********http://www.github.com/gilleskarougbe***********")
print("***********https://twiter.com/01karougbe****************")
print("***linkedin.com/in/essognim-gilles-karougbe-015979223***")
print("\n****************************************************\n")





######################******Methode1*****######################### 
def main1():
    for target in tqdm(Hosts_list):

        ether = scapy.Ether(src = 'e0:2b:e9:bc:45:a8',dst = 'ff:ff:ff:ff:ff:ff')
        arp = scapy.ARP(hwsrc = 'e0:2b:e9:bc:45:a8',psrc = '192.168.8.106' ,pdst = target)
        pkt = ether/arp
        result = scapy.srp(pkt,verbose = 0)
        #type(result) = tuple with len(result) = 2
        try:
            Qanswer = result[0][0]
            #Qanswer[0] -----> 
            #Qanswer[1] -----> reply
            MAC = Qanswer[1].hwsrc
            Host = dict()
            Host['ip'] = target
            Host['mac'] = MAC
            clients.append(Host)
        except:
            pass
    return clients

Hosts = main1()
print(Hosts)


######################******Methode2*****#########################
#####Sending ICMP echo-request to broadcast to get live hosts#####
def main2():
    for target in tqdm(Hosts_list):
        a = scapy.Ether(src='e0:2b:e9:bc:45:a8',dst='ff:ff:ff:ff:ff:ff')
        b = scapy.IP(src='192.168.0.153',dst= target,proto='icmp')
        c = scapy.ICMP()

        pkt = a/b/c
        result = scapy.srp(pkt,verbose = 0)

        try:
            Qanswer = result[0][0]
            #Qanswer[0] -----> request
            #Qanswer[1] -----> reply
            MAC = Qanswer[1].src
            Host = dict()
            Host['ip'] = target
            Host['mac'] = MAC
            clients.append(Host)
        except:
            pass
        
    return clients

Hosts = main2()
print(Hosts)
