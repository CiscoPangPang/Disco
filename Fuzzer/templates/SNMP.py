#!/usr/bin/python
from cplib import *
from cplib import __DEBUG__, conn, db_cursor
from scapy.all import *
import random

def send_SNMP(oid='1.3.', timeout=0): # res means oid as well
    dst = '192.168.1.55'
    sport = 161
    dport = 161
    #community = fuzz('public')
    community = 'public'

    sr1(
        IP(dst = dst) / UDP(sport = sport, dport = dport) / SNMP(community = community, PDU = SNMPget(varbindlist = [SNMPvarbind(oid = oid)])),
        timeout=timeout
    )

def SNMP_fuzz(fuzzer):
    global conn, db_cursor

    timeout = fuzzer.timeout
    protocol = fuzzer.protocol
    pause = fuzzer.pause
    primkey = fuzzer.primkey

    if __DEBUG__ != 1: time.sleep(0.2)

    data = ''
    while True:
        if pause == True:
            break

        res = '1.3.' # base on default template (if doesn't include 1.3., it always returns joint.~~)
        cnt = random.randrange(2000)
        for i in range(cnt):
            if random.randrange(0, 2) == 1:
                res += str(random.randrange(0xff)) + '.'
            else:
                res += '0.' # null-byte overwrite

        dst = '192.168.1.55'
        sport = 161
        dport = 161#random.randrange(0xffff)
        community = fuzzer.fuzz('public')
        oid = res[:-1] # made this code to remove last .(dot)

        # primkey | mac_addr | data | log_symbols
        sql = "INSERT INTO `pkt_data` (`idx`, `primkey`, `protocol`, `mac_addr`, `data`, `log_symbols`, `save_date`) VALUES(NULL, %s, %s, %s, %s, %s, NOW()) ;";

        db_cursor.execute(sql, (primkey, 'SNMP', get_mac(), oid, ''))
        conn.commit()

        sr1(
            IP(dst = dst) / UDP(sport = sport, dport = dport) / SNMP(community = community, PDU = SNMPget(varbindlist = [SNMPvarbind(oid = oid)])),
            timeout=timeout
        )
