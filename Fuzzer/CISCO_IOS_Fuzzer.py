# -*- encoding: utf-8 -*-
from cplib import *
from cplib import __DEBUG__, conn, db_cursor

#------------------------------------------------------------------------
# load protocol module in "template" directory manually at here
# they must have `protocol_name`_fuzz() and send_`protocol_name`()
#------------------------------------------------------------------------
sys.path.append(os.getcwd() + "\\templates")
from SNMP import *
from DHCP import *
#------------------------------------------------------------------------

readline.parse_and_bind("tab: complete")

def main():
    global protocol, timeout

    cmds = {
        "SNMP": None,
        "DHCP": None,
        "NDP": None
    }

    completer = CmdCompleter(cmds)
    readline.set_completer(completer.complete)

    valid_protocol = 0
    while True:
        protocol = raw_input("[>] Which Protocol do you want to fuzz?: ")
        for name, dict_ in cmds.items():
            if name == protocol:
                valid_protocol = 1
                break
        if valid_protocol:
            break
        else:
            print("[-] Press [Tab] to show available protocols")

    while True:
        try:
            timeout = raw_input("[>] How about setting timeout for the Fuzzer?(default: 0.1): ")
            if timeout == '':
                timeout = 0
            
            timeout = float(timeout)
            break
        except:
            print("[!] Invalid timeout value")
            continue

    print("[+] Start Fuzzing!")
    fuzzer.set_timeout(timeout)
    fuzzer.set_protocol(protocol)
    # execute a fuzzer with the protocol what you choose
    eval("%s_fuzz(fuzzer)" % protocol)

__DEBUG__ = 0

if __name__ == "__main__":
    if __DEBUG__ == 1:
        print("[+] DEBUG MODE enabled")

    fuzzer = CiscoIOSFuzzer()

    version = '0.8'
    primkey = 'no'
    print("-=" * 38)
    if __DEBUG__ != 1: time.sleep(0.1)
    print(R"""
    _____ ____   _____   ______ _    _ __________________ _____  
   |_   _/ __ \ / ____| |  ____| |  | |___  /___  /  ____|  __ \ 
     | || |  | | (___   | |__  | |  | |  / /   / /| |__  | |__) |
     | || |  | |\___ \  |  __| | |  | | / /   / / |  __| |  _  / 
    _| || |__| |____) | | |    | |__| |/ /__ / /__| |____| | \ \ 
   |_____\____/|_____/  |_|     \____//_____/_____|______|_|  \_\\""")

    if __DEBUG__ != 1: time.sleep(1)
    print("\n - Version: %s\n" % version)
    if __DEBUG__ != 1: time.sleep(0.5)
    print("-="*38)
    if __DEBUG__ != 1: time.sleep(0.5)
    print("\tMessage(s): \n\n")
    if __DEBUG__ != 1: time.sleep(1)

    start_main = threading.Thread(target=main, args=())
    start_main.start()

    if __DEBUG__ == 1:
        print("[!] main() function Thread has been started!\n")

    cmdreceiver = threading.Thread(target=fuzzer.cmd_receiver, args=())
    cmdreceiver.start()

    if __DEBUG__ == 1:
        print("[!] Server Command Receiver Thread has been started!")
