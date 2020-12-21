from scapy.all import Ether, ARP, srp, sniff, conf
import sys



def getMac(ip):
    #will return the mac address for IP, this function has a few differences from the ARPSpoofer.py getMacAddr function
    p = Ether(dst ='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def isARPReal(pkt):
    if pkt.haslayer(ARP):  # if ARP packet
        # 2 is an ARP reply (is-at) so we are only looking for replies.
        if pkt[ARP].op == 2:
            try:
                # gets real MAC address of sender
                actualMac = getMac(pkt[ARP].psrc)
                # gets MAC address from the packet that is passed
                responseMac = pkt[ARP].hwsrc

                if actualMac != responseMac:  # if they're different send print a warning
                    print(
                        f"[WARNING] IP SPOOFING DETECTED! REAL-MAC: {actualMac}, FAKE-MAC: {responseMac}")

            except IndexError:
                pass  # if we can't find the real mac


if __name__ == "__main__":
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = conf.iface

    # store=False will discard sniffed packets
    sniff(store=False, prn=isARPReal, iface=iface)
