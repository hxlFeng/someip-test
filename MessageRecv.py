from scapy.all import *
import PackageStructure as someip
def dul(packet):
    sipPacket = someip.WholePackage(packet[Raw])
    if sipPacket.msg_id.srv_id == 0xffff:
        print("----------------------recv")

sniff(count=0,prn=dul,filter="udp and port 50001",iface="enp4s0f1")