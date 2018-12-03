import threading
import time
import select
import os
import sys
from math import floor, ceil
from common import *


class File:
    def __init__(self, filename, filesize):
        self.filename = filename
        self.filesize = filesize

    def __repr__(self):
        return "Filename: {}, size: {}".format(self.filename, self.filesize)


CHUNK_SIZE = 1400
BUFFER_SIZE = 64 * 1024  # for receive window. 64KB

FILE_LIST_PORT = 8005
FILE_REQUEST_PORT = 8006
CHUNK_PORT = 8007
ACK_PORT = 8008

threads = {}
all_files = {}
chunks_to_be_received = {}  # maps sequence numbers to chunks
chunks_to_be_sent = {}
chunk_numbers_waited_from_each_user = {}
num_chunks = 0
thread_list = {}
destination_IP = ""
mutex = threading.Lock()
socket_for_file_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket_for_file_send.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def get_my_file_list():
    my_files = []
    path = "files/"
    files = os.listdir(path)
    for name in files:
        full_path = os.path.join(path, name)
        file_size = os.path.getsize(full_path)
        f = File(name, file_size)
        my_files.append(f)

    return my_files


def print_all_files():
    for key in all_files:
        print("-" * 35)
        print("        {}\n".format(key))
        for file in all_files[key]:
            print("{:20} {:5} bytes".format(file.filename, file.filesize))
        print("-" * 35)


def share_my_list(target_ip):
    # protocol -> sender_IP;filename*filesize/filename*filesize/
    packet = get_own_ip() + ";"
    for file in get_my_file_list():
        packet += file.filename + "*" + str(file.filesize) + "/"

    send_tcp_packet(target_ip, FILE_LIST_PORT, packet)


# Returns size of a file with given filename
def get_file_size(filename):
    global all_files
    for key in all_files:
        lst = all_files[key]
        for i in lst:
            if i.filename == filename:
                return i.filesize


# Returns a list of users who has a file with given filename
def has_file(filename):
    user_list = []      # user list who has this file
    for key in all_files:
        lst = all_files[key]
        for dosya in lst:
            if dosya.filename == filename:
                user_list.append(key)

    return user_list


# Protocol -> seq_num;rwnd;my_IP
def send_ACK(seq_num, rwnd, dest_ip):
    packet = str(seq_num) + ";" + str(rwnd) + ";" + get_own_ip()
    send_udp_packet(dest_ip, ACK_PORT, packet)


def process_packet(packet, total_chunk_number):
    global chunks_to_be_received
    global num_chunks
    global mutex
    global chunk_numbers_waited_from_each_user
    meta_data = packet[:100].decode("utf-8")   # First 100 bytes is metadata
    seq_num = meta_data.split(";")[0]
    receiving_ip = meta_data.split(";")[1]
    chunk = packet[100:]    # last 1400 bytes is file chunk

    if (len(packet) == 1500) or (int(seq_num) == total_chunk_number-1):
        if seq_num not in chunks_to_be_received:
            chunks_to_be_received[seq_num] = chunk
            chunk_numbers_waited_from_each_user[receiving_ip] -= 1
        remaining_chunk_number_from_receiving_ip = chunk_numbers_waited_from_each_user[receiving_ip]
        total_chunk_number_left = sum(chunk_numbers_waited_from_each_user.values())
        if total_chunk_number_left != 0:
            rwnd_for_receiving_ip = ceil(BUFFER_SIZE * remaining_chunk_number_from_receiving_ip / total_chunk_number_left)
            rwnd_for_receiving_ip = max(rwnd_for_receiving_ip, 1500)
        else:
            rwnd_for_receiving_ip = 0

        send_ACK(seq_num, rwnd_for_receiving_ip, receiving_ip)
    if len(chunks_to_be_received) == num_chunks:
        try:
            mutex.release()
        except:
            pass    # already released


def listen_file_chunks():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", CHUNK_PORT))
    s.setblocking(0)
    while True:
        result = select.select([s], [], [])
        data = result[0][0].recv(1600)
        packet = data
        process_packet(packet, num_chunks)


# Protocol -> seq_num;rwnd;dest_ip
def listen_ACK():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", ACK_PORT))
    s.setblocking(0)

    global thread_list
    global chunks_to_be_sent
    global destination_IP

    while True:
        result = select.select([s], [], [])
        data = result[0][0].recv(1024)
        packet = data.decode("utf-8")

        seq_num = packet.split(";")[0]
        rwnd = packet.split(";")[1]

        # Stop the thread
        try:
            thread_list[int(seq_num)].is_run = False
        except:
            pass
        thread_list.pop(int(seq_num), None)

        number_of_packets_being_send = len(thread_list)
        max_pack_num = floor(int(rwnd) / 1500)
        new_packet_number = max_pack_num - number_of_packets_being_send

        if new_packet_number > 0 and len(chunks_to_be_sent) > 0:
            for i in range(int(new_packet_number)):
                # Start a new packet sender thread
                try:
                    index_chunk_to_be_sent, temp_chunk = chunks_to_be_sent.popitem()
                    new_thread = threading.Thread(target=send_single_chunk, daemon=True, args=(temp_chunk, destination_IP))
                    try:
                        new_thread.start()
                        thread_list[index_chunk_to_be_sent] = new_thread
                    except:
                        # Too many threads bug fix
                        new_thread.is_run = False
                        chunks_to_be_sent[index_chunk_to_be_sent] = temp_chunk
                except:
                    pass


# protocol -> sender_IP;filename*filesize/filename*filesize/
def update_file_list(packet):
    global all_files
    sender_ip = packet.split(";")[0]
    file_list = packet.split(";")[1]
    files = []
    for file in file_list.split("/"):
        if "*" not in file:
            all_files[sender_ip] = files
            return

        filename = file.split("*")[0]
        filesize = file.split("*")[1]
        f = File(filename, int(filesize))
        files.append(f)


# Listen TCP after broadcasting to get all the files in the network
def listen_available_files():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((get_own_ip(), FILE_LIST_PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        packet = data.decode("utf-8")
        update_file_list(packet)


# Listen UDP for file list broadcasts.
# If anyone broadcast for available files, send him a list of all the files I have
def listen_file_list_requests():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", FILE_LIST_PORT))
    s.setblocking(0)

    while True:
        result = select.select([s], [], [])
        data = result[0][0].recv(1024)
        packet = data.decode("utf-8")
        # Protocol -> "files;dest_ip"
        dest_ip = packet.split(";")[1]
        share_my_list(dest_ip)


# Listen TCP for file requests.
# Protocol -> requested_filename;chunk_start;chunk_end;destination_ip;rwnd
def listen_file_requests():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((get_own_ip(), FILE_REQUEST_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        data = conn.recv(1700)
        packet = data.decode("utf-8")

        requested_filename = packet.split(";")[0]
        chunk_start = int(packet.split(";")[1])
        chunk_end = int(packet.split(";")[2])
        request_ip = packet.split(";")[3]
        rwnd = packet.split(";")[4]
        send_file_chunks(requested_filename, chunk_start, chunk_end, request_ip, rwnd)


def send_single_chunk(packet, ip_addr):
    global socket_for_file_send
    try:
        t = threading.currentThread()
        while getattr(t, "is_run", True):
            socket_for_file_send.sendto(packet, (ip_addr, CHUNK_PORT))
            time.sleep(1)
    except Exception as e:
        print(e)
        sys.exit()


def send_file_chunks(filename, chunk_start, chunk_end, dest_ip, rwnd):
    global chunks_to_be_sent
    global thread_list
    global destination_IP
    global num_chunks

    destination_IP = dest_ip

    max_pack_num = floor(int(rwnd) / 1500)
    num_chunks = chunk_end - chunk_start + 1

    index = chunk_start
    chunks_to_be_sent = {}
    thread_list = {}
    filename = "files/" + filename
    sender_ip = get_own_ip()

    with open(filename, 'rb') as file:
        _ = file.read(CHUNK_SIZE * chunk_start)  # Skip first bytes until starting chunk
        while chunk_end+1 > index:
            data = file.read(CHUNK_SIZE)
            meta_data = bytes("{};{};".format(str(index), sender_ip), "utf-8")
            padding_size = 100 - len(meta_data)
            padding = padding_size * bytes("\0", "utf-8")
            packet = meta_data + padding + data     # protocol -> seq_num;chunk
            chunks_to_be_sent[index] = packet
            index += 1

    for i in range(int(min(max_pack_num, num_chunks))):
        index_chunk_to_be_sent, temp_chunk = chunks_to_be_sent.popitem()
        t = threading.Thread(target=send_single_chunk, daemon=True, args=(temp_chunk, dest_ip))
        t.is_run = True
        thread_list[index_chunk_to_be_sent] = t
    for thread in thread_list.copy().values():
        thread.start()


# Sends request to the seed users for parts of a file with given chunk indices.
# Protocol -> filename;chunk_start;chunk_end;dest_ip;rwnd
def request_file_chunks(filename, chunk_start, chunk_end, sender_ip, rwnd):
    packet = filename + ";" + str(chunk_start) + ";" + str(chunk_end) + ";" + get_own_ip() + ";" + str(int(rwnd))
    send_tcp_packet(sender_ip, FILE_REQUEST_PORT, packet)


# Finds who has the requested file and request all of them different parts of the file
def get_file(filename):
    global mutex
    mutex.acquire()
    users = has_file(filename)
    global chunk_numbers_waited_from_each_user
    if len(users) == 0:
        print("File not found!")
        return

    file_size = get_file_size(filename)
    global chunks_to_be_received
    global num_chunks
    chunks_to_be_received = {}
    num_chunks = ceil(file_size / CHUNK_SIZE)

    base_chunk, extra_chunk = divmod(num_chunks, len(users))
    index = 0
    rwnd_per_chunk = ceil(BUFFER_SIZE / num_chunks)

    for userIP in users:
        if extra_chunk != 0:
            chunk_interval = base_chunk+1
            extra_chunk -= 1
        else:
            chunk_interval = base_chunk
        if chunk_interval != 0:
            chunk_numbers_waited_from_each_user[userIP]=chunk_interval
            request_file_chunks(filename, index, index + chunk_interval-1, userIP, rwnd_per_chunk*chunk_interval)
            index += chunk_interval
    print("Downloading...")
    mutex.acquire()
    write_to_file(chunks_to_be_received, "files/{}".format(filename))
    print("File {} has been downloaded.".format(filename))
    try:
        mutex.release()
    except:
        pass    # already released


def list_available_files():
    global all_files
    all_files = {}
    broadcast("files;" + get_own_ip(), FILE_LIST_PORT)  # Protocol -> "files;dest_ip"
    print("Searching files. Please wait...")
    time.sleep(1)
    print_all_files()


def start():
    threading.Thread(target=listen_available_files, daemon=True).start()
    threading.Thread(target=listen_file_requests, daemon=True).start()
    threading.Thread(target=listen_file_list_requests, daemon=True).start()
    threading.Thread(target=listen_file_chunks, daemon=True).start()
    threading.Thread(target=listen_ACK, daemon=True).start()
