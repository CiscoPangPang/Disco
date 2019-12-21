# -*- encoding: utf-8 -*-
from cplib import *
from cplib import __DEBUG__, conn, db_cursor
from scapy.all import *
from subprocess import Popen, PIPE
from hexdump import hexdump as hd
import random
import struct


load_contrib("lldp")
p16 = lambda x : struct.pack(">H", x)
up16 = lambda x : struct.unpack(">H", x)[0]
random_uint8  = lambda : random.randrange(0x100)
random_uint16 = lambda : random.randrange(0x10000)
random_uint24 = lambda : random.randrange(0x1000000)
random_uint32 = lambda : random.randrange(0x100000000)
random_bool = lambda : random.choice([True, False])

lldp_multicast_mac = "01:00:0c:cc:cc:cc"

c4221_mac = "10:b3:d5:86:4c:c1"
c2911_mac = "cc:ef:48:b9:31:f1"
random_cisco_mac = "CC:EF:48:B9:de:ad"

LLDP_MSG_MAX_SIZE = 0x500

ORG_UNIQUE_CODE_CISCO = 0x000142

cisco_subtype_list = [ 0x01, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb ]

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


def init_LLDP():

	a = Ether(dst=lldp_multicast_mac, src=random_cisco_mac, type=0x88cc)

	b = LLDPDUChassisID() #1
	b.subtype = 0x04
	b.id = c2911_mac
	b._length = 7

	c = LLDPDUPortID() #2
	c.subtype = 0x05
	portid = mutate("I want to get zero day", 0x100)
	c.id = portid
	c._length = len(portid) + 1 #test please

	d = LLDPDUTimeToLive() #3
	d.ttl = 120

	return a/b/c/d


def create_LLDP_testcase(msg_seq=None):

	lldp_mandatory = init_LLDP()

	lldp_msg_list = lldp_mandatory

	current_msg_size = 0
	random_msg_size = LLDP_MSG_MAX_SIZE
	i = 0

	while True:

		if i != 0:
			try:
				current_msg_size = len(lldp_msg_list/LLDPDUEndOfLLDPDU())
			except:
				return

		i = i+1

		if current_msg_size > random_msg_size:
			break

		lldp_random_type = random.choice([4, 5, 6, 8, 127])

		if lldp_random_type == 4:
			lldp_random_msg = LLDPDUPortDescription()
			random_data = mutate("wally is so pretty and cute", 0x100)
			lldp_random_msg.description = random_data
			lldp_random_msg._length = len(random_data)

		elif lldp_random_type == 5:
			lldp_random_msg = LLDPDUSystemName()
			random_data = mutate("I want to die", 0x100)
			lldp_random_msg.system_name = random_data
			lldp_random_msg._length = len(random_data)

		elif lldp_random_type == 6:
			lldp_random_msg = LLDPDUSystemDescription()
			random_data = mutate("We are CiscoPangPang", 0x100)
			lldp_random_msg.description = random_data
			lldp_random_msg._length = len(random_data)

		elif lldp_random_type == 8:
			lldp_random_msg = LLDPDUManagementAddress()
			lldp_random_msg.management_address_subtype = random.choice(list(range(0x00, 0x1f)))
			lldp_random_msg.management_address = random_cisco_mac.replace(":","").decode("hex")
			lldp_random_msg.interface_numbering_subtype = random.choice(list(range(0x00, 0x1f)))
			lldp_random_msg.interface_number = random.choice(list(range(0x00, 0x4)))
			random_data = mutate("Where is my life?", 0x100 - 20)
			lldp_random_msg.object_id = random_data
			lldp_random_msg._oid_string_length = len(random_data)
			lldp_random_msg._lenth = 14 + len(random_data)

		elif lldp_random_type == 127:
			lldp_random_msg = LLDPDUGenericOrganisationSpecific()
			lldp_random_msg.org_code = ORG_UNIQUE_CODE_CISCO
			lldp_random_msg.subtype = random.choice(cisco_subtype_list)
			random_data = mutate("I want to get zero day", 0x100 - 10)
			lldp_random_msg._length = len(random_data) + 4
			lldp_random_msg.data = random_data


		try:
			if (i != 0) and (len(lldp_msg_list/LLDPDUEndOfLLDPDU()) > LLDP_MSG_MAX_SIZE):
				print "[!] what?? there's an error in 0x%04x" % (lldp_random_type)
				continue
		except:
			continue

		lldp_msg_list /= lldp_random_msg

	lldp_end = LLDPDUEndOfLLDPDU()

	return lldp_msg_list / lldp_end


def send_LLDP(pkt, timeout=0):
	srp1(pkt.decode('hex'), iface="Ethernet", timeout=timeout)

def LLDP_fuzz(fuzzer):
	global conn, db_cursor

	timeout = fuzzer.timeout
	protocol = fuzzer.protocol
	pause = fuzzer.pause
	primkey = fuzzer.primkey

	while True :

		pkt = create_LLDP_testcase()

		sql = "INSERT INTO `pkt_data` (`idx`, `primkey`, `protocol`, `mac_addr`, `data`, `log_symbols`, `save_date`) VALUES(NULL, %s, %s, %s, %s, %s, NOW()) ;";

		try:
			str(pkt)
		except:
			continue

		db_cursor.execute(sql, (primkey, 'LLDP', get_mac(), str(pkt).encode('hex'), ''))
		conn.commit()

		res = srp1(pkt, iface="Ethernet", timeout=timeout)



