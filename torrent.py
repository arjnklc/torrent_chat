import threading
import time
import select
import os
from common import *

class File:
    def __init__(self, filename, filesize):
        self.filename = filename
        self.filesize = filesize

    def __repr__(self):
        return "Filename: {}, size: {}".format(self.filename, self.filesize)



CHUNK_SIZE = 1400
BUFFER_SIZE = 64 * 1024  # 64KB

all_files = {}

threads = {}

FILE_LIST_PORT = 8005
FILE_REQUEST_PORT = 8006
CHUNK_PORT = 8007
ACK_PORT=8008

file_chunks = {}  # maps sequence numbers to chunks
chunks_to_be_sent={}
thread_list={}
destination_IP=""
rwnd_per_user = 0


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


# TODO
def print_all_files():

    print(all_files)


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

# Protocol -> seq_num;rwnd;dest_IP
def send_ACK(seq_num, rwnd, dest_ip):
    packet = str(seq_num) + ";" + str(rwnd) + ";" + dest_ip
    send_udp_packet(dest_ip, ACK_PORT, packet)


# TODO flow controlled UDP
def listen_file_chunks(filename, num_chunks):
    # TODO
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((get_own_ip(), CHUNK_PORT))
    s.setblocking(0)

    while True:

        result = select.select([s], [], [])
        data = result[0][0].recv(1600)
        packet = data.decode("utf-8")

        process_packet(packet,num_chunks)
        if len(file_chunks) == num_chunks:
            for i in range(len(file_chunks)):
                chunk = file_chunks[str(i)]
                append_to_file(chunk, filename)

            print("File {} has downloaded.".format(filename))
            return

# Protocol -> seq_num;rwnd;dest_ip
def listen_ACK():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((get_own_ip(), ACK_PORT))
    s.setblocking(0)

    global thread_list
    global chunks_to_be_sent
    global destination_IP
    while True:
        result = select.select([s], [], [])
        data = result[0][0].recv(1024)
        packet = data.decode("utf-8")

        # Protocol -> "files;dest_ip"
        seq_num = packet.split(";")[0]
        rwnd = packet.split(";")[1]

        # Stop the thread
        thread_list[seq_num].stop()
        index_chunk_to_be_sent, temp_chunk = chunks_to_be_sent.popitem()
        new_thread= threading.Thread(target=send_single_chunk, daemon=True,args=(temp_chunk,destination_IP))
        new_thread.start()
        thread_list[index_chunk_to_be_sent]=new_thread


def process_packet(packet,total_chunk_number):
    global rwnd_per_user
    meta_data = packet[:100].decode("utf-8")   # First 100 bytes is metadata
    seq_num = meta_data.split(";")[0]
    receiving_IP = meta_data.split(";")[1]
    chunk = packet[100:]  # last 1400 bytes is file chunk
    file_chunks[seq_num] = chunk
    if len(packet) == 1500 or seq_num == total_chunk_number:
        send_ACK(seq_num, rwnd_per_user, receiving_IP)


def update_file_list(packet):
    # protocol -> sender_IP;filename*filesize/filename*filesize/
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
    s.bind((get_own_ip(), FILE_LIST_PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        packet = data.decode("utf-8")
        print(packet)
        update_file_list(packet)


# Listen UDP for file list broadcasts.
# If anyone broadcast for available files, send him a list of all the files I have
def listen_file_list_requests():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((get_own_ip(), FILE_LIST_PORT))
    s.setblocking(0)

    while True:
        result = select.select([s], [], [])
        data = result[0][0].recv(1024)
        packet = data.decode("utf-8")
        # Protocol -> "files;dest_ip"
        dest_ip = packet.split(";")[1]
        print(packet)
        print(dest_ip)
        share_my_list(dest_ip)


# Listen TCP for file requests.
# Protocol -> requested_filename;chunk_start;chunk_end;destination_ip;rwnd
def listen_file_requests():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((get_own_ip(), FILE_REQUEST_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        data = conn.recv(1700)
        packet = data.decode("utf-8")
        print(len(packet))

        requested_filename = packet.split(";")[0]
        chunk_start = int(packet.split(";")[1])
        chunk_end = int(packet.split(";")[2])
        request_ip = packet.split(";")[3]
        rwnd = packet.split(";")[4]
        send_file_chunks(requested_filename, chunk_start, chunk_end, request_ip, rwnd)


def send_single_chunk(packet, ip_addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while True:
            s.sendto(packet, (ip_addr, CHUNK_PORT))
            time.sleep(1)
    except Exception as e:
        print(e)


def send_file_chunks(filename, chunk_start, chunk_end, dest_ip, rwnd):
    # TODO
    global chunks_to_be_sent
    global thread_list
    global destination_IP
    destination_IP=dest_ip
    packets_sent_but_not_acked = 0

    max_pack_num = int(rwnd / 1500)
    num_chunks = chunk_end - chunk_start + 1

    index = chunk_start
    chunks_to_be_sent={}
    thread_list={}
    filename = "files/" + filename
    sender_IP=get_own_ip()
    with open(filename, 'rb') as file:
        _ = file.read(CHUNK_SIZE * chunk_start)

        while chunk_end+1 > index:
            data = file.read(CHUNK_SIZE)
            meta_data = bytes("{};{};".format(str(index),sender_IP), "utf-8")
            index+=1
            padding_size = 100 - len(meta_data)
            padding = padding_size * bytes("\0", "utf-8")
            packet = meta_data + padding + data  # protocol -> seq_num;chunk
            # send_controlled_UDP(packet, port, dest_ip)
            chunks_to_be_sent[index] = data

    for i in range(max_pack_num):
        index_chunk_to_be_sent=i+chunk_start
        temp_chunk=chunks_to_be_sent[index_chunk_to_be_sent]
        chunks_to_be_sent.pop(index_chunk_to_be_sent, None)
        new_thread= threading.Thread(target=send_single_chunk, daemon=True,args=(temp_chunk,dest_ip))
        new_thread.start()
        thread_list[index_chunk_to_be_sent]=new_thread

# Sends request to the seed users for parts of a file with given chunk indices.
# Protocol -> filename;chunk_start;chunk_end;dest_ip;rwnd
def request_file_chunks(filename, chunk_start, chunk_end, sender_ip, rwnd):
    packet = filename + ";" + str(chunk_start) + ";" + str(chunk_end) + ";" + get_own_ip() + ";" + str(rwnd)
    print(packet)
    send_tcp_packet(sender_ip, FILE_REQUEST_PORT, packet)


# Finds who has the requested file and request all of them different parts of the file
def get_file(filename):
    users = has_file(filename)
    global rwnd_per_user
    if len(users) == 0:
        print("File not found.")
        return

    file_size = get_file_size(filename)
    global file_chunks
    file_chunks = {}
    num_chunks = int(file_size / CHUNK_SIZE) + 1

    threading.Thread(target=listen_file_chunks, args=(filename, num_chunks), daemon=True).start()

    chunk_interval = int(num_chunks / len(users) + 1)
    index = 0
    rwnd_per_user = BUFFER_SIZE / len(users)

    for user in users:
        request_file_chunks(filename, index, index + chunk_interval, user, rwnd_per_user)
        index += chunk_interval


def list_available_files():
    global all_files
    all_files = {}
    broadcast("files;" + get_own_ip(), FILE_LIST_PORT)  # Protocol -> "files;dest_ip"
    print("Searching files. Please wait...")
    time.sleep(3)
    print_all_files()


def start():
    threading.Thread(target=listen_available_files, daemon=True).start()
    threading.Thread(target=listen_file_requests, daemon=True).start()
    threading.Thread(target=listen_file_list_requests, daemon=True).start()
    threading.Thread(target=listen_ACK, daemon=True).start()