import hashlib
import socket
import threading
import hashlib
import time
import select


port = 5000


def get_name():
    return ""


def get_own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


# Return md5 of a file
def get_md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


# Broadcast given message to the network with UDP
def broadcast(message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(message.encode("utf-8"), ('<broadcast>', port))
    except Exception as e:
        print(e)


def ask_for_file(filename):
    broadcast("bana x dosyasi lazim")





def send_file(filename, dest_ip):
    pass




