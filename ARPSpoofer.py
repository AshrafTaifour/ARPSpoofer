from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys


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
    
def restore(target_ip, host_ip, verbose=True):
    #must reset everything or else the targets internet will crash
    #and the target will know an attack has happened
    target_mac = getMacAddr(target_ip) # the real MAC address of target
    host_mac = getMacAddr(host_ip)#the real MAC address of spoofed router
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac) # crafting the restoring packet
    send(arp_response, verbose=0, count=7)# sending the restoring packet
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

# for testing
targetIP = '192.168.0.1'

#enable_linuxip()
print(getMacAddr(targetIP))
restore('192.168.0.63',targetIP,True)
