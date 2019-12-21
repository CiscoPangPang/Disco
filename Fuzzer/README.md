# CISCO IOS Fuzzer

## Description

Fuzzer is a program that generates unexpected bugs and errors after randomly entering data into the system. Fuzzing is a popular method for security analysis methods as it can detect security vulnerabilities by finding serious flaws that lead to DoS, service fault or unintended behavior. vulnerabilities by finding serious flaws that lead to DoS, service fault or unintended behavior.

the mechanism of the CISCO IOS Network Fuzzer available for Cisco IOS is described in detail, and the reliability is demonstrated.

There are two clients that can proceed with fuzzing, and the Cisco IOS Monitor is
connected with the serial port to the Cisco Router. This provides management
for fuzzers such as Client Monitoring and crash storage during fuzzing.

After selecting the network protocol to analyze, use the packet transmission program
Scapy to match the structure of each network packet and set the field of the
Protocol Data Unit (PDU) with the probability of occurrence of the crash to
randomize values using Radamsa and PseudoRandom Number Generator (PRNG) to send
the packet.



## How to Use

### 1. CISCO_IOS_Monitor.py

To use this part of Framework, should run the CISCO IOS Monitor first, and then run the CISCO IOS Fuzzer. And CISCO IOS Montior can manage each Fuzzers, and when a crash occurs, CISCO IOS Monitor sends Fuzzer RESEND command for finding the Fuzzer which were crash occured.

- [RESEND]
  You can execute the RESEND command though, but RESEND command will be executed when a crash occurs in any Fuzzer.
  When you want to run the RESEND command, you just type "resend" on your command line of the CISCO IOS Monitor, you can run the RESEND command to find the crash occured by Fuzzer.
- [CLIENT LIST]
  You can type "show client list" to see the list of clients.
  And if you want to know about it more, you can append more with [alive, killed, ended]. (Ex: show client list alive)
- [HELP]
  You can type "help" to see the manual of the command line for CISCO IOS Monitior.



#### Example

```bash
CiscoPangPang>
quit   help   no     show   kill   exit   resend
```

When you want to see more commands about the command line of CISCO IOS Monitor, just press [Tab] in the command line to see more.



```bash
CiscoPangPang> show client list
IDX	NAME	IP	STATUS
11207	318AC42E	192.168.4.58	alive
208F4	318AC42E	192.168.4.58	alive
341ZB	827GA81B	192.168.4.12	alive
```

Available for showing the client list



```bash
CiscoPangPang> no show ftrace
[*] Disabled Ftrace print strings
```

Available for no showing FunctionTrace results



```bash
CiscoPangPang> show client list
IDX	NAME	IP	STATUS
11207	318AC42E	192.168.4.58	alive
208F4	318AC42E	192.168.4.58	alive
341ZB	827GA81B	192.168.4.12	alive

CiscoPangPang> [*] Crash Found!!
[*] Cisco IOS Monitor will save the crash on the database
```

When a crash occurs among the Fuzzers, CISCO IOS Monitor will discover that crash occurs, and will search the Fuzzer which were occured a crash trying to be finding



```bash
- Message(s):
[*] Pause Fuzzing
[*] Pause Fuzzing
[+] Waiting for rebooting.. (about 5 minutes)
[+] Send resend command to client 11207..
[-] Client 11207 Resend Command Done
[+] Send resend command to client 208F4..
```

When a crash occurs, then try to find the Fuzzer which were occured crash



### 2. CISCO_IOS_Fuzzer.py

- [Protocol Input]
  You should type the protocol name which you want to fuzz.
  We support 5 protocols for now, but will be added more. (NDP, SNMP, LLDP, CDP, DHCP)
- [Timeout Input]
  You should type the count of timeout variable, it will make your Fuzzer as more helpful to find vulnerabilities.
- [RESEND]
  You can execute the RESEND command though, but RESEND command will be executed when a crash occurs in any Fuzzer.



#### Example

fuzzing target protocol is SNMP

```bash
[>] Which Protocol do you want to fuzz?: SNMP
[>] How about setting timeout for the Fuzzer?(default: 0.1): 1
[+] Start Fuzzing!
Begin emission:
........Finished sending 1 packets.
...............................................................................
...............................................................................
........
Received 176 packets, got 0 answers, remaining 1 packets
Begin emission:
Finished sending 1 packets.
...............................................................................
...............................................................................
................
Received 176 packets, got 0 answers, remaining 1 packets
Begin emission:
Finished sending 1 packets.
...............................................................................
...............................................................................
...............................................................................
.....
Received 245 packets, got 0 answers, remaining 1 packets
Begin emission:
.Finished sending 1 packets.
...............................................................................
...............................................................................
...............................................................................
............
Received 253 packets, got 0 answers, remaining 1 packets
Begin emission:
Finished sending 1 packets.
...............................................................................
...............................................................................
..........................
Received 186 packets, got 0 answers, remaining 1 packets
Begin emission:
Finished sending 1 packets.
```





## Who?

`cppdbg` and `Disco Framework` are open source projects started by the `CiscoPangPang` team, the `KITRI Best of the Best` 8th project team.



## Contact

If you have any questions about this debugger or the Disco framework, please contact CiscoPangPang@gmail.com.
