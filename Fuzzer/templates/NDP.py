#!/usr/bin/python
<<<<<<< HEAD
def fuzz(): # Solicitation Fuzzing
    target_ip = "fec0::a5f4:ef4c:8461:5bd4"
    start_cmd = ["python", "C:\\Users\\PC_20\\Disco-Private\\Fuzzer\\templates"]
    target_ip = "127.0.0.1"
    start_cmd = ["python", "C:\\ftpd\\ftpd.py"]
    session = Session(
        target=Target(
            #connection=SocketConnection(target_ip, 21, proto="tcp"),
            #raw_layer_3 = SocketConnection(host=target_ip, proto='raw-l3'),
            raw_layer_3 = (host=target_ip, proto='raw-l3'),
            #procmon=pedrpc.Client(target_ip, 26002),
            #procmon_options={"start_commands": [start_cmd]},
        ),
        sleep_time=1,
    )

    # In order to fuzz with, it should be "Router" and "Neighbor"
    s_initialize("ndp");
    s_static("\x33\x33\x00\x00\x00")
    s_group("lastword", ["\x02", "\x01"])
    # The value above is dest addri

    s_static("\x00\x0c\x29\x79\x3c\xbd")
    # The value above is src addr
    s_static("\x86\xdd")
    # Type: IPv6

    s_static("\x60")
    s_group("flowlabel", ["\x02\xde\x05", "\x06\x39\x15"])
    # Flow Label

    s_static("\x00")
    s_group("paylen", ["\x08", "\x18"])
    # Payload Length

    s_static("\x3a")
    # Next Header: ICMPv6 (58)

    s_static("\xff")
    # Hop Limit: 255

    s_static("\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x0c\x29\xff\xfe\x79\x3c\xbd")
    # Source

    s_static("\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    s_group("dest", ["\x02", "\x01"])
    # Destination

    s_group("solicitation", ["\x85", "\x87"])
    # Type: *(Router, Neighbor) Solicitation

    s_static("\x00")
    # Code

    s_group("checksum", ["\x15\xf5", "\x13\xe6"])
    # Checksum

    s_static("\x00\x00\x00\x00")
    # Reserved

    #s_static("\x00"*16)
    # Target Address (it is empty when it's Router Solicitation)
	
    session.connect(s_get("ndp")) # call connect() func to fuzz with
=======
from scapy.all import *
import time
import random

dst = 'FEC0::A5F4:EF4C:8461:5BD4'
src = 'fe80::a5f4:ef4c:8461:5bd3'

timeout = 0.01

i = 0

while True:
    mac = 'D' + str(random.randrange(0, 10)) + '-3D-' + str(random.randrange(0, 10)) + 'E-' + str(random.randrange(0, 10)) + 'D-F8-1E'.replace('-', ':')
    mac = 'D4-3D-7E-CD-F8-1E'.replace('-', ':')
>>>>>>> 66518377e0b8a91a8e1a1f470ffda46835070f59

    base = IPv6(dst=dst)
    router_solicitation = ICMPv6ND_RS()
    src_ll_addr = ICMPv6NDOptSrcLLAddr(lladdr=mac)
    packet = base/router_solicitation/src_ll_addr

    if i == 300:
        time.sleep(10)
        i = 0
    sr1(packet, timeout=timeout)
    i += 1
