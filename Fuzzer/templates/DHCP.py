#!/usr/bin/python
from cplib import *
from cplib import __DEBUG__, conn, db_cursor
from scapy.all import *

def relay_agent_information(): # 82nd option
   return "\x52"

def send_DHCP(res, timeout):
    global conn, db_cursor

    if __DEBUG__ != 1: time.sleep(0.2)

    data = ''

    localiface = 'Ethernet'
    requestMAC = 'd4:3d:7e:cd:f8:1e'
    myhostname = 'vector'
    localmac = get_if_hwaddr(localiface)
    localmacraw = requestMAC.replace(':', '').decode('hex')
    end = "\xff\x00"

    res = res.decode('hex')

    dhcp_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options=[('message-type', 'discover')])/chr(82)/"\xff\x01\x02"/res/end

    sr1(dhcp_discover, iface=localiface, timeout=timeout)

def DHCP_fuzz(fuzzer):
    global conn, db_cursor
    
    timeout = fuzzer.timeout
    protocol = fuzzer.protocol
    pause = fuzzer.pause
    primkey = fuzzer.primkey

    if __DEBUG__ != 1: time.sleep(0.2)

    data = ''

    localiface = 'Ethernet'
    requestMAC = 'd4:3d:7e:cd:f8:1e'
    myhostname = 'vector'
    localmac = get_if_hwaddr(localiface)
    localmacraw = requestMAC.replace(':', '').decode('hex')
    end = "\xff\x00"

    while True:
        if pause == True:
            break

        res = fuzzer.create_random_value()

        dhcp_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options=[('message-type', 'discover')])/relay_agent_information()/"\xff\x01\x02"/res/end 

        # primkey | mac_addr | data | log_symbols
        sql = "INSERT INTO `pkt_data` (`idx`, `primkey`, `protocol`, `mac_addr`, `data`, `log_symbols`, `save_date`) VALUES(NULL, %s, %s, %s, %s, %s, NOW()) ;";

        db_cursor.execute(sql, (primkey, 'DHCP', get_mac(), res.encode('hex'), ''))
        conn.commit()

        srp1(dhcp_discover, iface=localiface, timeout=timeout)
