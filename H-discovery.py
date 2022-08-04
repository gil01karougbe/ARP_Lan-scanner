"""Run this program using the syntax bellow:
    sudo python3 H-discovery.py -n network_addr -p prefix_length

Disclaimer:This is for educational purpose only !!!!!Do not use against any network you own or don't have permission to test.
"""

import scapy.all as scapy
from tqdm import tqdm
import ipaddress as ipaddr
import os
import sys



def in_sudo_mode():
    """If the user doesn't run the program with super user privileges, don't allow them to continue."""
    if not 'SUDO_UID' in os.environ.keys():
        print("You are not root!\nTry running this program with sudo privileges.")
        exit()

def get_cmd_arguments():
    """ This function validates the command line arguments supplied when running the program"""
    Args = None
    # Ensure that the user has specified 9 arguments
    if len(sys.argv) != 5:
        print("Error!!!!! You specified less or more than 5 arguments")
        return Args
    elif sys.argv[1]=='-n' and sys.argv[3]=='-p':
        try:
            L = []
            L.append(sys.argv[2])
            L.append(sys.argv[4])
            Args = L
        except:
            print("Invalid command-line arguments check the documentation")
            
    return Args


def get_host_list(IP,PREFIX_LENGTH):
    network = ipaddr.IPv4Network(IP +'/'+ PREFIX_LENGTH)
    Hosts_list = [str(ip) for ip in network]
    return Hosts_list   

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


def scanner(Hosts_list):
    clients = list()
    for target in tqdm(Hosts_list):

        ether = scapy.Ether()
        arp = scapy.ARP(pdst = target)
        pkt = ether/arp
        result = scapy.srp(pkt,verbose = 0)
        #type(result) = tuple with len(result) = 2
        try:
            Qanswer = result[0][0]
            #Qanswer[0] -----> request
            #Qanswer[1] -----> reply
            MAC = Qanswer[1].hwsrc
            Host = dict()
            Host['ip'] = target
            Host['mac'] = MAC
            clients.append(Host)
        except:
            pass
    return clients


#check sudo  mode
in_sudo_mode()

#get commande line arguments
Args = get_cmd_arguments()
"""
    Args[0]----->network address
    Args[1]----->prefix length
"""
#hosts list
Hosts_list = get_host_list(Args[0],Args[1])

#scanning
live_hosts = scanner(Hosts_list)
print(live_hosts)
