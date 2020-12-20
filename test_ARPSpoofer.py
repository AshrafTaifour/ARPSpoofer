#This only works on linux, this program has to be run as root user

from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys
import subprocess
import unittest
from ARPSpoofer import enable_linuxip, getMacAddr, spoof, restore



TARGET_IP = '192.168.1.123'
HOST_IP = '192.168.1.69' #this is the address we're pretending to be
ROUTER_IP = '192.168.1.1'
YOUR_ROUTER_MACADDR = '94:10:3e:08:be:a2' #use your own router's mac address to check if the function is working properly.


#This will be used for the spoof function testing

local_mac = ARP().hwsrc
host_mac = getMacAddr(HOST_IP)
SPOOF_TEST_STRING = f'[+] Sent to {ROUTER_IP} : {HOST_IP} is-at {local_mac}'
RESTORE_TEST_STRING = f'[+] Sent to {ROUTER_IP} : {HOST_IP} is-at {host_mac}'


#enable_linuxip()

class TestARPSpoofer(unittest.TestCase):


    def test_getMacAddr(self):
        exp_ret = YOUR_ROUTER_MACADDR
        actual_ret = getMacAddr(ROUTER_IP)

        #print(f'actual result = {actual_ret}, expected result = {exp_ret}')

        assert exp_ret == actual_ret



    def test_spoof(self):
        exp_ret = SPOOF_TEST_STRING
        actual_ret = spoof(ROUTER_IP, HOST_IP)

        assert exp_ret == actual_ret


    def test_restore(self):
        exp_ret = RESTORE_TEST_STRING
        actual_ret = restore(ROUTER_IP, HOST_IP)
        
        assert exp_ret == actual_ret

        
if __name__ == '__main__':
    unittest.main()


#TestARPSpoofer.test_getMacAddr(1)
