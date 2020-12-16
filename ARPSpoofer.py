from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys

def enable_linuxip():
    #EnablesIP Forward in linux
    filepath = "/proc/sys/net/ipv4/ip_forward"#linux os variable that allows the
    with open(filepath) as f:                 #ip forwording to be turned on 
        if f.read() == 1:                     #or off
            return # 1 is already enabled and 0 means disabled
    with open(filepath, "w") as f:
        print(1, file=f)
