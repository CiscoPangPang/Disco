# -*- encoding: utf-8 -*-
from cplib import *
from cplib import __DEBUG__, conn, db_cursor
from scapy.all import *
from subprocess import Popen, PIPE
from hexdump import hexdump as hd
import random
import struct

load_contrib("cdp")
p16 = lambda x : struct.pack(">H", x)
up16 = lambda x : struct.unpack(">H", x)[0]
random_uint8  = lambda : random.randrange(0x100)
random_uint16 = lambda : random.randrange(0x10000)
random_uint24 = lambda : random.randrange(0x1000000)
random_uint32 = lambda : random.randrange(0x100000000)
random_bool = lambda : random.choice([True, False])

cdp_multicast_mac = "01:00:0c:cc:cc:cc"

# IEEE 802.3 vs Ethernet II
# Dot3()'s len must be less than 0x0600
CDP_MSG_MAX_SIZE = 0x5FF - len(Dot3()) + len(LLC()) + len(SNAP()) + len(CDPv2_HDR())

cisco_mac_prefix_list = ["10:b3:d5:", "cc:ef:48:", "00:e0:1e:", "00:0b:be:"]

def mutate(payload, max_len=None):
    try:
        radamsa = ["radamsa.exe", '-n', '1', '-']
        p = Popen(radamsa, stdin=PIPE, stdout=PIPE)
        mutated_data = p.communicate(payload)[0]
    except:
        print "Could not execute 'radamsa'."
        sys.exit(1)

    if max_len is not None:
        return mutated_data[:max_len]
    else:
        return mutated_data


def wrapping_CDP(mut_cdp):
    # IEEE 802.3 Ethernet
    mut_dot3 = Dot3()
    mut_dot3.dst = cdp_multicast_mac
    mut_dot3.src = random.choice(cisco_mac_prefix_list) + ("%02x:%02x:%02x" % (random_uint8(), random_uint8(), random_uint8()))
    # mut_dot3.len = random_uint16()

    # Logical-Link Protocol
    mut_LLC = LLC()
    mut_LLC.dsap = 0xaa # SNAP (0xaa)
    mut_LLC.ssap = 0xaa # SNAP (0xaa)
    mut_LLC.ctrl = 0x03 # Control field?? wtf is this byte?

    # Subnetwork Access Protocol
    mut_SNAP = SNAP()
    mut_SNAP.OUI  = 0x00000C  # Organization Code: 00:00:0c (Cisco Systems, Inc)
    mut_SNAP.code = 0x2000    # PID: CDP (0x2000)

    mut_dot3.len = len(mut_LLC) + len(mut_SNAP) + len(mut_cdp)
    fuzz_pkt = mut_dot3/mut_LLC/mut_SNAP/mut_cdp
    return fuzz_pkt


# generic mutator
def create_CDP_testcase1(msg_seq=None):
    cdp_msg_list = []
    # random_msg_size = random.randrange(CDP_MSG_MAX_SIZE)
    random_msg_size = CDP_MSG_MAX_SIZE
    while True:
        # https://github.com/secdev/scapy/blob/2be23d9/scapy/contrib/cdp.py#L70
        # scapy said CDP TLV range equal 0x0001 ~ 0x001a
        # https://github.com/wireshark/wireshark/blob/e206eb2/epan/dissectors/packet-cdp.c#L160
        # wireshark said CDP TLV range equal 0x0001 ~ 0x001f and 0x1000 ~ 0x100d
        current_msg_size = sum(len(cdp_msg) for cdp_msg in cdp_msg_list)
        if current_msg_size > random_msg_size:
            while current_msg_size > random_msg_size:
                cdp_msg_list.pop()
                current_msg_size = sum(len(cdp_msg) for cdp_msg in cdp_msg_list)
            break

        if msg_seq is not None:
            if len(msg_seq) == 0:
                # msg_seq = None
                break
            else:
                cdp_random_type = msg_seq[0]
                msg_seq = msg_seq[1:]
        else:
            cdp_random_type = random.choice(list(range(1, 0x20)) + list(range(0x1000, 0x1002)))

        # some message type needs diffrent values
        if cdp_random_type in [0x0002, 0x0016]:
            if cdp_random_type == 0x0002:
                cdp_random_msg = CDPMsgAddr()
            else:
                cdp_random_msg = CDPMsgMgmtAddr()

            cdp_random_msg.naddr = 2 # random_uint8()
            for _ in range(cdp_random_msg.naddr):
                if random_bool():
                    # IPv4
                    cdp_addr_record = CDPAddrRecordIPv4()
                    cdp_addr_record.ptype = 0x01 # "NLPID"
                    cdp_addr_record.plen = 0x01
                    cdp_addr_record.proto = "\xcc"
                    cdp_addr_record.addrlen = 4
                    cdp_addr_record.addr = "%d.%d.%d.%d" % (random_uint8(), random_uint8(), random_uint8(), random_uint8())
                else:
                    # IPv6
                    cdp_addr_record = CDPAddrRecordIPv6()
                    cdp_addr_record.ptype = 0x02 # "802.2"
                    cdp_addr_record.plen = 0x08 
                    cdp_addr_record.proto = "\xaa\xaa\x03\x00\x00\x00\x86\xdd" # https://github.com/secdev/scapy/blob/2be23d9/scapy/contrib/cdp.py#L127
                    cdp_addr_record.addrlen = 16
                    cdp_addr_record.addr = ":".join("%04x" % (random_uint16()) for _ in range(8))

                cdp_random_msg.addr.append(cdp_addr_record)

            while ((current_msg_size + len(cdp_random_msg)) > random_msg_size) and len(cdp_random_msg.addr) != 0:
                cdp_random_msg.addr.pop()
                cdp_random_msg.naddr -= 1

        elif cdp_random_type == 0x0003:
            cdp_random_msg = CDPMsgPortID()
            cdp_random_msg.iface = mutate("GigabitEthernet0/0/0", max_len=CDP_MSG_MAX_SIZE-current_msg_size-len(cdp_random_msg))

        elif cdp_random_type == 0x0004:
            cdp_random_msg = CDPMsgCapabilities()
            cdp_random_msg.cap = random_uint32()

        elif cdp_random_type == 0x0007:
            cdp_random_msg = CDPMsgIPPrefix()
            mut_val = mutate("\x14\x00\x00\x00\x18", 5)
            cdp_random_msg.defaultgw = mut_val

        elif cdp_random_type == 0x0008:
            cdp_random_msg = CDPMsgProtoHello()
            cdp_random_msg.oui = 0x00000C
            if random_bool():
                cdp_random_msg.protocol_id = 0x0112 # TYPE_HELLO_CLUSTER_MGMT
                cdp_random_msg.data = mutate("\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x01\x02\x20\xFF\x00\x00\x00\x00\x00\x00\x00\x0B\xBE\x18\x9A\x40\xFF\x00\x00",  27)
            else:
                cdp_random_msg.protocol_id = random_uint16()
                cdp_random_msg.data = mutate("X" * 0x100, max_len=CDP_MSG_MAX_SIZE-current_msg_size-len(cdp_random_msg))

        elif cdp_random_type == 0x000a:
            cdp_random_msg = CDPMsgNativeVLAN()
            cdp_random_msg.vlan = random_uint16()

        elif cdp_random_type == 0x000b:
            cdp_random_msg = CDPMsgDuplex()
            cdp_random_msg.duplex = random_uint8() # {0x00: "Half", 0x01: "Full"}...so what?

        elif cdp_random_type == 0x000e:
            cdp_random_msg = CDPMsgVoIPVLANReply()
            cdp_random_msg.status = random_uint8()
            cdp_random_msg.vlan = random_uint16()

        elif cdp_random_type == 0x000f:
            cdp_random_msg = CDPMsgVoIPVLANQuery()
            cdp_random_msg.unknown1 = random_uint8()
            cdp_random_msg.vlan = random_uint16()
            cdp_random_msg.unknown2 = mutate("X" * 0x100, max_len=CDP_MSG_MAX_SIZE-current_msg_size-len(cdp_random_msg))

        elif cdp_random_type == 0x0010:
            cdp_random_msg = CDPMsgPower()
            cdp_random_msg.power = random_uint16()

        elif cdp_random_type == 0x0011:
            cdp_random_msg = CDPMsgMTU()
            cdp_random_msg.mtu = random_uint16()

        elif cdp_random_type == 0x0012:
            cdp_random_msg = CDPMsgTrustBitmap()
            cdp_random_msg.trust_bitmap = random_uint8()

        elif cdp_random_type == 0x0013:
            cdp_random_msg = CDPMsgUntrustedPortCoS()
            cdp_random_msg.untrusted_port_cos = random_uint8()
        else:
            cdp_random_msg = CDPMsgGeneric()
            cdp_random_msg.type = cdp_random_type
            cdp_random_msg.val = mutate("X" * 0x100, max_len=CDP_MSG_MAX_SIZE-current_msg_size-len(cdp_random_msg))

        if len(str(cdp_random_msg)) > CDP_MSG_MAX_SIZE:
            print "[!] what?? there's an error in 0x%04x, length == 0x%x!" % (cdp_random_type, len(str(cdp_random_msg)))
            continue

        cdp_random_msg.len = len(cdp_random_msg)
        cdp_msg_list.append(cdp_random_msg)

    mut_cdp = CDPv2_HDR()
    mut_cdp.vers = random.choice([1,2])
    mut_cdp.ttl = random_uint8()
    mut_cdp.msg = cdp_msg_list[:]
    return wrapping_CDP(mut_cdp)


def send_CDP(pkt, timeout=0):
    srp1(pkt, iface="Ethernet", timeout=timeout)


def CDP_fuzz(fuzzer):
    '''
        CDPMsgDeviceID(),
        CDPMsgSoftwareVersion(),
        CDPMsgPlatform(),
        CDPMsgAddr(),
        CDPMsgPortID(),
        CDPMsgCapabilities(),
        CDPMsgIPPrefix(),
        CDPMsgVTPMgmtDomain(),
        CDPMsgDuplex(),
        CDPMsgMgmtAddr(),
        CDPAddrRecordIPv4(),
    '''
    timeout = fuzzer.timeout
    protocol = fuzzer.protocol
    pause = fuzzer.pause
    primkey = fuzzer.primkey

    msg_type_seq = [1, 5, 6, 2, 3, 4, 7, 9, 0xb, 0x16]

    while True:
        random.shuffle(msg_type_seq)
        pkt = create_CDP_testcase1(msg_type_seq)
        sql = "INSERT INTO `pkt_data` (`idx`, `primkey`, `protocol`, `mac_addr`, `data`, `log_symbols`, `save_date`) VALUES(NULL, %s, %s, %s, %s, %s, NOW()) ;";

        db_cursor.execute(sql, (primkey, 'CDP', get_mac(), pkt, ''))
        conn.commit()
        srp1(pkt, iface="Ethernet", timeout=timeout)
