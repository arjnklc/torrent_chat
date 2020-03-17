import socket
import hashlib


def get_name():
    return "Arjen"

def get_own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()

    return ip


# Broadcast given message to the given port
def broadcast(message, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((get_own_ip(), 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(message.encode("utf-8"), ('<broadcast>', port))
    except Exception as e:
        print("Broadcast error! {}".format(e))


# Returns md5 hash digest of a given string
def get_md5(s):
    result = hashlib.md5(s.encode("utf-8"))
    return result.hexdigest()
	
# Returns md5 hash digest of a given file
def get_md5_file(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()	
	

# Sends a TCP packet to a specified ip address and port.
# Default timeout is 3 seconds.
def send_tcp_packet(ip_addr, port, packet, timeout=3):
    if ip_addr == get_own_ip():
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip_addr, port))
        s.sendall(packet.encode("utf-8"))
    except Exception as e:
        print("Sending TCP packet to {} is unsuccessful. {}".format(ip_addr, e))


# Sends a UDP packet to a specified ip address and port.
# Default timeout is 3 seconds.
def send_udp_packet(ip_addr, port, packet, timeout=3):
    if ip_addr == get_own_ip():
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet.encode("utf-8"), (ip_addr, port))
        s.close()
    except Exception as e:
        print("Sending UDP packet to {} is unsuccessful. {}".format(ip_addr, e))


def write_to_file(chunks, filename):
    with open(filename, 'wb') as f:
        try:
            for i in range(len(chunks)):
                f.write(chunks[str(i)])
        except Exception as e:
            print("Error while writing to file. {}".format(e))
