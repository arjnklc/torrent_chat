import socket
import hashlib


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


# Broadcast given message to the given port
def broadcast(message, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(message.encode("utf-8"), ('<broadcast>', port))
    except Exception as e:
        print(e)


# Return md5 of a file
def get_md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


"""
Sends a tcp packet to a specified ip address and port. 
Default timeout is 3 seconds.
"""
def send_tcp_packet(ip_addr, port, packet, timeout=3):
    if ip_addr == get_own_ip():
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip_addr, port))
        s.sendall(packet.encode("utf-8"))
    except:
        print("Sending packet to {} is unsuccessful".format(ip_addr))


def append_to_file(bytes, filename):
    with open(filename, 'ab') as f:
        f.write(bytes)
