#!/usr/bin/python
from __future__ import print_function
from cplib import *
import serial
import datetime
from _thread import *

readline.parse_and_bind('tab: complete')

def serial_connect():
    return serial.Serial(
        port='COM3',
        baudrate=9600,
        parity="N",
        stopbits=1,
        bytesize=8,
        timeout=8
    )

def stop_fuzz():
    global client_list

    for client in client_list:
        sock = client[4]
        sock.send("pause")
        print("[*] Pause fuzzing")

def resend():
    global client_list
    #Wait End Message from client

    for client in client_list:
        sock = client[4]
        sock.send('resend')
        print("[+] Send resend command to client %s.." % client[0])
        #wait for crelient end
        if sock.recv(1024) == 'done':
            print("[-] Client %s Resend Command Done" % client[0])
            continue

    for client in client_list:
        sock = client[4]
        #say end to all clients
        sock.send('resend_end')

    print("[*] Resend Done")

def mon_repeat():
    global ftrace_flag
    if __DEBUG__ != 1: time.sleep(4)
    print("[*] Check Router alive..")
    if __DEBUG__ != 1: time.sleep(1.3)
    console = serial_connect()

    if not console.isOpen():
        print("[!] Can't open CISCO serial port!")
        sys.exit(-1)
    else:
        print("[-] Router Connected!")

    if __DEBUG__ != 1: time.sleep(1)
    print("[*] Start CISCO IOS Monitor!")

    while True:
        console.write("\n")
        console_data = console.read(console.inWaiting())

        date = datetime.datetime.today().strftime("%Y-%m-%d-%S").split('-')
        to_day = date[0] + date[1] + date[2]
        sec = date[3]
        if 'signal' in console_data:
            console.write("\n")
            console_data2 = console.read(console.inWaiting())
            if __DEBUG__ != 1: time.sleep(0.1)
            if __DEBUG__ != 1: time.sleep(1)
            print("[*] Crash Found!!")
            print('')
            print("[*] CISCO IOS Monitor will save the crash on the database")
            print('')
            if __DEBUG__ != 1: time.sleep(3)

            print("-="*40)
            if __DEBUG__ != 1: time.sleep(0.5)
            if __DEBUG__ != 1: time.sleep(0.2)
            print("-="*40)
            if __DEBUG__ != 1: time.sleep(0.5)
            print("\n - Message(s): \n")
            if __DEBUG__ != 1: time.sleep(1.5)

            stop_fuzz()

            print("[+] Waiting for rebooting.. (about 5 minutes)")
            if __DEBUG__ != 1: time.sleep(2)

            resend()

        if "called" in console_data:
            if ftrace_flag is 1:
               print(console_data) 

def iosmon_main():
    while True:
        mon_repeat()
        if __DEBUG__ != 1: time.sleep(60)

def db_exec(curs, sql):
    curs.execute(sql)

def init_db(curs):
    sql = []
    base1 = '5345542053514c5f4d4f4445203d20224e4f5f4155544f5f56414c55455f4f4e5f5a45524f223b'
    base2 = '5345542074696d655f7a6f6e65203d20222b30303a3030223b'
    pc_alive_check = '435245415445205441424c45206070635f616c6976655f636865636b6020280a2020606964786020696e7428313129204e4f54204e554c4c2c0a2020606d61635f6164647260207661726368617228313829204e4f54204e554c4c2c0a202060616c697665602074696e79696e74283429204e4f54204e554c4c2c0a2020606c6f675f74696d6560206461746574696d65204e4f54204e554c4c0a2920454e47494e453d496e6e6f44422044454641554c5420434841525345543d757466383b'
    pkt_data = '435245415445205441424c452060706b745f646174616020280a2020606964786020696e7428313129204e4f54204e554c4c2c0a2020606d61635f616464726020696e7428313829204e4f54204e554c4c2c0a202060646174616020746578742c0a2020606c6f675f73796d626f6c736020746578742c0a202060736176655f6461746560206461746574696d65204e4f54204e554c4c0a2920454e47494e453d496e6e6f44422044454641554c5420434841525345543d757466383b'
    pc_alive_check_pri = '414c544552205441424c45206070635f616c6976655f636865636b600a2020414444205052494d415259204b455920286069647860293b'
    pkt_data_pri = '414c544552205441424c452060706b745f64617461600a2020414444205052494d415259204b455920286069647860293b'
    pc_alive_check_mod = '414c544552205441424c45206070635f616c6976655f636865636b600a20204d4f4449465920606964786020696e7428313129204e4f54204e554c4c204155544f5f494e4352454d454e543b'
    pkt_data_mod = '414c544552205441424c452060706b745f64617461600a20204d4f4449465920606964786020696e7428313129204e4f54204e554c4c204155544f5f494e4352454d454e543b'

    sql.append(base1)
    sql.append(base2)
    sql.append(pc_alive_check)
    sql.append(pkt_data)
    sql.append(pc_alive_check_pri)
    sql.append(pkt_data_pri)
    sql.append(pc_alive_check_mod)
    sql.append(pkt_data_mod)

    for qry in sql:
        if __DEBUG__ == 1:
            print("--------------------------------------------")
            print("- SQL which are executing -")
            print(qry.decode('hex'))
            print("-END----------------------------------------")
        db_exec(curs, qry.decode('hex'))

def mon_for_web():
    is_db_init = 0 # initialize the db setting
    if is_db_init == 1:
        init_db(curs)

    print("[*] Start Monitor for web!")
    if __DEBUG__ != 1: time.sleep(1)

    app.run()

def print_client(status='alive'):
    global client_list

    ex_status = ['alive', 'killed', 'ended']

    print ("\n|-------------------------------------------|")
    print ("|  IDX   |   NAME    |     IP      | STATUS |")
    print ("|-------------------------------------------|")

    for elements in client_list:
        for j in range(0, 4):
            if status in ex_status:
                if elements[3] == status:
                    print("|" + elements[j], end=' | ')
            else:
                print("|" + elements[j], end=' | ')
        print("")

    print ("|-------------------------------------------|\n")

def search_not_killed():
    global client_list
    arr = []
    for element in client_list:
        if element[3] != 'killed':
            arr.append(element[0])
    return arr

def search(dirname):
    filenames = os.listdir(dirname)
    d = []
    for filename in filenames:
        full_filename = os.path.join(dirname, filename)
        ext = os.path.splitext(full_filename)[-1]
        if ext == '.crash':
            d.append(full_filename.split('/')[-1].split('.crash')[0])
    return d

def print_help():
    print(open('data/help.txt', 'r').read())

def client_commander():
    global ftrace_flag
    global kill_cli
    if __DEBUG__ != 1: time.sleep(7)

    print("\n\n") # for cleaning

    crash_dir = 'crashes_info/'
    while True:
        try:
            cmds = {
                'show': {
                    "client": {
                        'list': {
                            'alive': None, 
                            'killed': None, 
                            'ended': None 
                        }
                    }, 
                    "crash": {
                        "list": None
                    }, 
                    "ftrace": None
                },
                'no': {
                    "show": {
                        "ftrace": None
                    }
                },
                'kill': {}, 
                'resend': {}, 
                'help': None,
                'quit': None,
                'exit': None
            }

            for idx in search_not_killed():
                cmds['kill'][idx] = None # looking for the item which has not been killed

            for name in search(crash_dir):
                cmds['show']['crash'][name] = None # Add dictionary on commands variable

            completer = CmdCompleter(cmds)
            readline.set_completer(completer.complete)

            line = str(raw_input('CiscoPangPang> '))
            line = line.split(" ")

            del cmds['kill'] # for cleaning the variables as well

            if line[0] == "show":
                if line[1] == "client":
                    if line[2] == "list":
                        print_client()
                        if line[3]:
                            print_client(line[3])
                elif line[1] == "crash":
                    if line[2]:
                        if os.path.isfile(crash_dir + line[2] + '.crash'):
                            print("Filename: %s.crash" % line[2])
                            print(open(crash_dir + line[2] + '.crash', 'r').read())
                elif line[1] == "ftrace":
                    ftrace_flag = 1;
                    print("[*] Enabled Ftrace print strings")
                else:
                    continue
            elif line[0] == "no":
                if line[1] == "show":
                    if line[2] == "ftrace":
                        ftrace_flag = 0;
                        print("[*] Disabled Ftrace print strings")
            elif line[0] == "kill":
                if line[1]:
                    kill_cli = line[1] # kill name(line[1])
                    print("[*] Trying to kill %s! Please wait." % kill_cli)
            elif line[0] == "quit":
                print("[Closing..]")
                sys.exit(-1)
            elif line[0] == "exit":
                sys.exit(-1)
            elif line[0] == "help":
                print_help()
            elif line[0] == '':
                # because there is nothing
                continue
            else:
                print("%s: command not found" % line[0])
                continue  

        except KeyboardInterrupt:
            continue
        except Exception as e:
            continue

print_lock = threading.Lock()
        
def threaded(c):
    global client_list
    global kill_cli
    ip = ''
    mac = ''
    primkey = ''

    while True:
        try:
            if kill_cli: # kill_cliname should be same with primary key(primkey)
                if kill_cli == primkey:
                    c.send("kill")

                    for element in client_list:
                        if element[0] == primkey:
                            element[3] = 'killed'

                    c.close()
                    print("\n[*] Killed %s(%s)[%s] Client" % (mac, ip, primkey))
                    kill_cli = ''
                    sys.exit(-1)

            try:
                ready = select.select([c], [], [], 0.01)
                if ready[0]:
                    data = c.recv(20000)
                else:
                    data = '' # for no waiting

            except Exception as e:
                if __DEBUG__ == 1:
                    print("[!] First part of disconnection")

                print("[*] Disconnected from %s(%s)[%s]" % (mac, ip, primkey))
                for element in client_list:
                    if element[0] == primkey:
                        element[3] = 'ended'
                c.close()
                break

            if not data:
                continue

            if "credential" in data:
                data = data.split('|')
                if __DEBUG__ == 1:
                    print("[!] The information of client: ")
                    print(data)
                ip = data[1]
                mac = data[2]
                primkey = data[3]
                print("\n[*] Client %s(%s)[%s] Connected" % (mac, ip, primkey))
                client_list.append(
                    # [key]  [mac] [ip] [status] [socket]
                    [primkey, mac, ip, "alive", c]
                )
                if __DEBUG__ == 1:
                    print("[!] the client list: ")
                    print(client_list)
        except Exception as e:
            print("Error: ")
            print(e)
            import traceback
            print("[Exception] %s" % e)
            print(traceback.format_exc())

def bind_serv(host='', port=12345):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))

    s.listen(5)
  
    while True:
        c, addr = s.accept()
        print("[!] New connection detected")
        start_new_thread(threaded, (c,))
        
    s.close()

__DEBUG__ = 0

if __name__ == "__main__":
    if __DEBUG__ == 1:
        print('[*] DEBUG MODE enabled')

    ftrace_flag = 0
    kill_cli = ''
    client_list = []
    crash_occurs = 0
    version = '0.4'
    print("-="*38)
    if __DEBUG__ != 1: time.sleep(0.1)
    print(R"""
   _____ ____   _____   __  __  ____  _   _ _____ _______ ____  _____  
   |_   _/ __ \ / ____| |  \/  |/ __ \| \ | |_   _|__   __/ __ \|  __ \ 
    | || |  | | (___   | \  / | |  | |  \| | | |    | | | |  | | |__) | 
    | || |  | |\___ \  | |\/| | |  | | . ` | | |    | | | |  | |  _  /  
   _| || |__| |____) | | |  | | |__| | |\  |_| |_   | | | |__| | | \ \  
   |_____\____/|_____/  |_|  |_|\____/|_| \_|_____|  |_|  \____/|_|  \_\ """)
    if __DEBUG__ != 1: time.sleep(1)

    print("\n - Version: %s\n" % version)
    if __DEBUG__ != 1: time.sleep(0.5)

    print("-="*38)
    if __DEBUG__ != 1: time.sleep(0.5)

    print("\tMessage(s): \n\n")
    if __DEBUG__ != 1: time.sleep(1)

    print("[*] Check database alive")
    if __DEBUG__ != 1: time.sleep(2)

    curs = db_conn().cursor() # cursor to db

    if __DEBUG__ == 1:
        print("[!] HTTP Server Thread started!")

    #Serial Connection Thread
    ios_monitor = threading.Thread(target=iosmon_main, args=())
    ios_monitor.start()

    if __DEBUG__ == 1:
        print("[!] IOS Monitor Thread started!")

    #Command Line Thread
    client_cmd = threading.Thread(target=client_commander, args=())
    client_cmd.start()

    if __DEBUG__ == 1:
        print("[!] Client Commander Thread started!")

    #Server Bind Thread
    bind_serv = threading.Thread(target=bind_serv, args=())
    bind_serv.start()

    if __DEBUG__ == 1:
        print("[!] Server Binder Commander Thread started!")
