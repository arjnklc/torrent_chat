import threading
import time
import select
import os
from common import *


class File:
    def __init__(self, filename, filesize):
        self.filename = filename
        self.filesize = filesize


CHUNK_SIZE = 1400

all_files = {}

FILE_LIST_PORT = 8005
FILE_REQUEST_PORT = 8006
CHUNK_PORT = 8007

file_chunks = {}  # maps sequence numbers to chunks


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


# TODO flow controlled UDP
def listen_file_chunks(filename, num_chunks):
    # TODO
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", CHUNK_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        packet = data.decode("utf-8")

        # TODO
        process_packet(packet)
        if len(file_chunks) == num_chunks:
            for i in range(len(file_chunks)):
                chunk = file_chunks[str(i)]
                append_to_file(chunk, filename)

            print("File {} has downloaded.".format(filename))
            return


def process_packet(packet):
    meta_data = packet[:100].decode("utf-8")   # First 100 bytes is metadata
    seq_num = meta_data.split(";")[0]
    chunk = packet[100:]  # last 1400 bytes is file chunk
    file_chunks[seq_num] = chunk


def update_file_list(packet):
    # protocol -> sender_IP;filename*filesize/filename*filesize/
    global all_files
    sender_ip = packet.split(";")[0]
    file_list = packet.split(";")[1]
    files = []
    for file in file_list.split("/"):
        if "*" not in file:
            return

        filename = file.split("*")[0]
        filesize = file.split("*")[1]
        f = File(filename, filesize)
        files.append(f)

    all_files[sender_ip] = files


# Listen TCP after broadcasting to get all the files in the network
def listen_available_files():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", FILE_LIST_PORT))
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
# Protocol -> requested_filename;chunk_start;chunk_end;destination_ip
def listen_file_requests():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", FILE_REQUEST_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        packet = data.decode("utf-8")

        requested_filename = packet.split(";")[0]
        chunk_start = int(packet.split(";")[1])
        chunk_end = int(packet.split(";")[2])
        request_ip = packet.split(";")[3]
        send_file_chunks(requested_filename, chunk_start, chunk_end, request_ip)


def send_file_chunks(filename, chunk_start, chunk_end, dest_ip):
    # TODO
    # check if i have the file
    seq_num = chunk_start

    with open(filename, 'rb') as file:
        while chunk_end > seq_num:
            data = file.read(CHUNK_SIZE)
            meta_data = bytes(str(seq_num) + ";", "utf-8")
            padding_size = 100 - len(meta_data)

            padding = padding_size * bytes("\0", "utf-8")

            packet = meta_data + padding + data   # protocol -> seq_num;chunk
            # send_controlled_UDP(packet, port, dest_ip)
            send_tcp_packet(dest_ip, CHUNK_PORT, packet)
            #process_packet(packet)
            seq_num += 1


# Sends request to the seed users for parts of a file with given chunk indices.
# Protocol -> filename;chunk_start;chunk_end;dest_ip
def request_file_chunks(filename, chunk_start, chunk_end, sender_ip):
    packet = filename + ";" + str(chunk_start) + ";" + str(chunk_end) + ";" + get_own_ip()
    send_tcp_packet(sender_ip, FILE_REQUEST_PORT, packet)


# Finds who has the requested file and request all of them different parts of the file
def get_file(filename):
    users = has_file(filename)
    if len(users) == 0:
        print("File not found.")
        return

    file_size = get_file_size(filename)
    global file_chunks
    file_chunks = {}
    num_chunks = int(file_size / CHUNK_SIZE) + 1
    listen_file_chunks(filename, num_chunks)

    chunk_interval = num_chunks / len(users) + 1
    index = 0
    for user in users:
        request_file_chunks(filename, index, index + chunk_interval, user)
        index += chunk_interval


def list_available_files():
    global all_files
    all_files = {}
    broadcast("files;" + get_own_ip(), FILE_LIST_PORT)  # Protocol -> "files;dest_ip"
    print("Searching files. Please wait...")
    time.sleep(3)
    print(all_files)


def start():
    threading.Thread(target=listen_available_files, daemon=True).start()
    threading.Thread(target=listen_file_requests, daemon=True).start()
    threading.Thread(target=listen_file_list_requests, daemon=True).start()
