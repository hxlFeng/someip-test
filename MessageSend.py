import sys,os
path=os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(str(path))

from scapy.all import *
import PackageStructure as someip

def MakeSOMEIPPackage():
    package = someip.WholePackage()
    package.msg_id.srv_id = 0xffff
    package.msg_id.sub_id = 0x0
    package.msg_id.method_id = 0x0000

    package.req_id.client_id = 0xdead
    package.req_id.session_id = 0xbeef

    package.msg_type = 0x01
    package.retcode = 0x00

    payload = bytearray(255)
    payload[0] = 0x00
    payload[1] = 0x01
    payload[2] = 0x02
    payload[3] = 0x03
    payload[4] = 0x04
    payload[5] = 0x05
    payload[6] = 0x06
    payload[7] = 0x07
    payload[8] = 0x08
    payload[9] = 0x09
    payload[10] = 0x0A
    payload[11] = 0x0B
    payload[12] = 0x0C
    payload[13] = 0x0D
    payload[14] = 0x0E
    payload[15] = 0x0F
    del payload[16:]
    package.add_payload(bytes(payload))

    return package

def MakeEthPackage():
    package = Ether()/IP(src="192.168.0.103",dst="192.168.0.105")/UDP(sport=30490,dport=50001)/MakeSOMEIPPackage()
    return package

sendp(MakeEthPackage(),iface="enp4s0f1")

      
