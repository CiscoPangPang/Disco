#!/usr/bin/python
from scapy.all import *
from uuid import getnode
import hashlib
import os
import sys
import random
import time
import readline
import pymysql
import threading
import select

__DEBUG__ = 0

def uuid(leng=12):
    charset = 'abcdef0123456789'
    result = ''
    for i in range(leng):
        result += charset[random.randrange(len(charset))]

    return result

def addslashes(s):
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("'", "\\'")
    return s

def get_ip(): # return local ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    
    return ip

def get_mac():
    mac = str(getnode()) # get mac
    enc = hashlib.md5()
    enc.update(mac)
    mac = enc.hexdigest()[0:8].upper()
    return mac

def db_conn():
    host = 'localhost'
    user = 'root'
    password = 'aaaa'
    db = 'cisco_db'
    charset = 'utf8'
    return pymysql.connect(
        host=host,
        user=user,
        password=password,
        db=db,
        charset=charset
    )

class CmdCompleter:
    def __init__(self, cmds):
        self.cmds = cmds

    def traverse(self, tokens, tree, tail):
        if tree is None:
            return []
        elif len(tokens) == 0:            
            return [x + ' ' if tree[x] else x for x in tree.keys()]

        token = tokens[0]
        if len(tokens) == 1:
            if token in tree.keys() and tail:
                return self.traverse(tokens[1:], tree[token], tail)
            else:
                return [x + ' ' if tree[x] else x for x in tree.keys() if x.startswith(token)]
        else:
            return self.traverse(tokens[1:], tree[token], tail)
        return []

    def complete(self, text, state):
        buf = readline.get_line_buffer()
        tokens = buf.split()
        tail = True if buf[-1:] == ' ' else False
        results = self.traverse(tokens, self.cmds, tail) + [None]
        return results[state]

class CiscoIOSFuzzer():
    def __init__(self):
        self.timeout = 0
        self.protocol = ''
        self.pause = False
        self.primkey = 'no'

    def set_timeout(self, timeout):
        self.timeout = timeout
    
    def set_protocol(self, protocol):
        self.protocol = protocol

    def create_random_string(self, str_length=12):
        charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = ""
        for i in range(str_length):
            result += charset[random.randrange(len(charset))]

        return result

    def fuzz(self, seed="", testcase_length_max=100):
        result = ''
        fuzz_prefix = ''
        fuzz_postfix = ''

        fuzz_prefix_range   = random.randrange(1, (testcase_length_max // 2) - len(seed))
        fuzz_postfix_range  = random.randrange(1, (testcase_length_max // 2) - len(seed))

        mutated_seed = seed[random.randrange(len(seed)) : random.randrange(0xff) % len(seed)]

        # create prefix fuzz string
        if random.randrange(0, 2) == 1:
            for _ in range(fuzz_prefix_range):
                fuzz_prefix += chr(random.randrange(0, 0x100))

        # create postfix fuzz string
        if random.randrange(0, 2) == 1:
            for _ in range(fuzz_postfix_range):
                fuzz_postfix += chr(random.randrange(0, 0x100))

        result = fuzz_prefix + mutated_seed + fuzz_postfix
        return result

    def db_execute(self, db_cursor, sql_query):
        db_cursor.execute(sql_query)
        result = []
        rows = db_cursor.fetchall()

        if __DEBUG__ == 1:
            print("[+] querying '%s' result:" % sql_query)
            print(rows)

        for row in rows:
            result.append(row)

        return result

    def monitor_connect(self, host, port, retry=1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((host, port))
            except:
                if retry > 50:
                    print("[!] maximum retry count exceed")
                    return

                print("[+] Connect to the CISCO IOS Monitor... [RETRY %d]" % retry)
                retry += 1
                self.monitor_connect(host, port, retry)

            ip = get_ip()
            mac = get_mac()
            self.primkey = self.create_random_string(5)
            info = "credential|%s|%s|%s" % (ip, mac, self.primkey)
            s.send(info)
        except socket.error, msg:
            print("[!] Couldn't connect to the socket-server: %s\n terminating program" % msg)
            if __DEBUG__ != 1: time.sleep(1)
            sys.exit(1)

        print("\n[+] Connected with %s!" % self.primkey)
        if __DEBUG__ != 1: time.sleep(0.2)

        return s

    # pkt == packet
    def send_recent_pkt(self, num):
        global db_cursor
        primkey = self.primkey
        protocol = self.protocol

        sql_query = "SELECT `data` FROM `pkt_data` WHERE `primkey` = '%s' AND `protocol` = '%s' ORDER BY `save_date` DESC LIMIT 0, %d;" % (primkey, protocol, num)

        row_list = self.db_execute(db_cursor, sql_query)

        for row in row_list:
            eval("send_%s(row, self.timeout)" % protocol)

    def resend(self, s):
        self.send_recent_pkt(100)

        s.send("done")

        while True:
            cmd = s.recv(1024)

            if cmd == "resend_end":
                self.pause = False
                print("[+] resend() finished")
                break

        eval("%s_fuzz()" % protocol)

    def create_random_value(self):
        table = ""
        for i in range(0x100):
            table += chr(i)
        buf = "".join(random.sample(table, len(table)))
        return buf * 4

    def cmd_receiver(self):
        host = "192.168.4.34"
        port = 12345

        if __DEBUG__ != 1: time.sleep(0.2)
        s = self.monitor_connect(host, port)

        while True:
            try:
                data = 0
                ready = select.select([s], [], [], 0.01)
                if ready[0]:
                    data = s.recv(1024)

                if not data:
                    continue
                elif data == "kill":
                    print("")
                    print("[!] Killed by CISCO IOS Monitor!")
                    if __DEBUG__ != 1: time.sleep(2)
                    sys.exit(-1)
                elif data == "resend":
                    resend(s)
                elif data == "pause":
                    self.pause = True
            except socket.error as err:
                if err.errno == errno.ECONNREFUSED:
                    print(os.strerror(err.errno))
                    sys.exit(-1)
                elif err.errno == errno.EWOULDBLOCK:
                    print("fuck")
                    continue
                else:
                    raise


conn = db_conn()
db_cursor = conn.cursor()
