#!/usr/bin/env python3
import scapy.all as scapy
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP or Target range.")
    options = parser.parse_args()
    if not options.target:
        parser.error("Please specify target args ! see more info use -h or --help")
    else:
        return options

def scan(ip):
    ans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip), timeout=2, verbose=False)[0]
    return ans

def display_result(ans):
    print("IP \t\t\t\t MAC Address\n" + "_" * 50)
    counter = 1
    for item in ans:
        if (counter == 1):
            print(item[1].psrc + "\t\t\t" + item[1].hwsrc)
            counter = counter + 1
            continue
        print(item[1].psrc + "\t\t\t" + item[1].hwsrc)

options = get_args()
result = scan(options.target)
display_result(result)








