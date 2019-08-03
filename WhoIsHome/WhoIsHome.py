# -*- coding: utf-8 -*-
import scapy.all as scapy
import json, os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--debug", "--logs", "--verbose",dest='logs', help="Run script with logs", action="store_true")
#parser.add_argument("--name", "--add", dest='name', help="name of new tracking to be added")
#parser.add_argument("--delete", help="name of the search you want to delete")
#parser.add_argument('--refresh', dest='refresh', action='store_true', help="refresh search results")
#parser.set_defaults(refresh=False)
#parser.add_argument('--list', dest='list', action='store_true', help="print a list of current trackings")
#parser.set_defaults(list=False)
args = parser.parse_args()

file_db="db.json"

GATEWAY = "192.168.1.254/24"

known_hosts_dict = {}
new_hosts_dict = {}

def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# https://medium.com/@777rip777/simple-network-scanner-with-python-and-scapy-802645073190

def scan():
    ip                    = GATEWAY
    arp_request           = scapy.ARP(pdst=ip)
    broadcast             = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list         = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]
    clients_list = []
    mac_address_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        mac_address_list.append(element[1].hwsrc)
    return mac_address_list

def check_who_is_home(mac_address_list):
    global known_hosts_dict
    global new_hosts_dict
    at_home = []
    for m in mac_address_list:
        x = known_hosts_dict.get(m)
        if(x==None):
            new_hosts_dict[m] = ""
        if x and not x in at_home:
            w=[x]
            at_home = at_home + w
    
    if len(at_home)==0:
        print("Sembra che a casa non ci sia nessun host conosciuto.")
    elif len(at_home)==1:
        print( "A casa c'è {}.".format(at_home[0]) )
    else:
        print("A casa ci sono {}".format(at_home))
    for host in new_hosts_dict:
        print("Nuovo host: {}".format(host))

def load():
    global known_hosts_dict
    global new_hosts_dict
    if os.path.exists(file_db):
        with open(file_db) as json_file:
            data = json.load(json_file)
            known_hosts_dict    = data["known_hosts_dict"]
            new_hosts_dict      = data["new_hosts_dict"]
            if args.logs:
                print("-----------LOAD DATA-------------")
                print(data)
    
def save():
    data = {"known_hosts_dict": known_hosts_dict, "new_hosts_dict": new_hosts_dict}
    if args.logs:
        print("-----------SAVE DATA-------------")
        print(data)
    with open(file_db, 'w+') as outfile:
        json.dump(data, outfile, indent=4)

if __name__ == "__main__":
    load()
    scan_result = scan()
    if args.logs:
        print("-----------Scan result-----------")
        print(scan_result)
    check_who_is_home(scan_result)
    if args.logs:
        print("-----------Nuovi hosts-----------")
        print(new_hosts_dict)
    save()