import threading
import time
import select
import torrent

from common import *


DISCOVERY_PORT = 5000
MESSAGE_PORT = 5001

DISCOVERY_INTERVAL = 60  # seconds

online_users = {}
incoming_hashes = {}
sent_hashes = {}


def print_online_users():
    print("-----------Online Users-------------")

    for username, ip_addr in online_users.items():
        print("{0}  =>  {1}".format(username, ip_addr))

    print(36 * "-")


def broadcast_continuously():
    while True:
        try:
            discover()
        except Exception as e:
            print("broadcast error!")

        time.sleep(DISCOVERY_INTERVAL)


def discover():
    online_users.clear()
    packet = "0;{0};{1};;;".format(get_own_ip(), get_name())
    broadcast(packet, DISCOVERY_PORT)
    update_hashes()


def defragment_discovery_packet(packet):
    try:
        args = packet.split(";")
        type = args[0]
        sender_ip = args[1]
        sender_name = args[2].lower()
        return type, sender_ip, sender_name
    except:
        print("invalid packet")
        return -1, "", ""


def update_hashes():
    for key in list(incoming_hashes):
        if key not in online_users:
            del incoming_hashes[key]

    for key in list(sent_hashes):
        if key not in online_users:
            del sent_hashes[key]


"""
Continuously listens 5000 UDP port for discovery packets.
if the incoming packet type is 0, send a packet with type 1
if the packet type is 1, which means it is an answer to 
the discovery packets, add this user to the online_users list
"""
def listen_udp_discovery_packets():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", DISCOVERY_PORT))
    s.setblocking(0)

    while True:
        result = select.select([s], [], [])
        data = result[0][0].recv(1024)
        packet = data.decode("utf-8")

        packet_type, sender_ip, sender_name = defragment_discovery_packet(packet)
        answer = "1;{0};{1};{2};{3};".format(get_own_ip(), get_name(), sender_ip, sender_name)
        send_tcp_packet(sender_ip, DISCOVERY_PORT, answer)



def listen_tcp_discovery_packets():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.bind((get_own_ip(), DISCOVERY_PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        packet = data.decode("utf-8")
        packet_type, sender_ip, sender_name = defragment_discovery_packet(packet)
        online_users[sender_name] = sender_ip


def defragment_message_packet(packet):
    try:
        args = packet.split(";")
        sender_ip = args[0]
        hash = args[1]
        message = args[2]
        return sender_ip, hash, message
    except:
        print("invalid packet.")
        print(">>")
        return -1, "", ""


def get_username_from_ip(sender_ip):
    for key in online_users.keys():
        if online_users[key] == sender_ip:
            return key

    return sender_ip


"""
Continuously listens 5001. port for message packets.
if the hashes do not match, warn the user about man in the middle attack.1
"""
def listen_message_packets():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", MESSAGE_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        packet = data.decode("utf-8")
        sender_ip, hash, message = defragment_message_packet(packet)

        print("Message '" + message + "' from " + get_username_from_ip(sender_ip))

        if sender_ip in sent_hashes and hash != get_md5(sent_hashes[sender_ip]):
            if sender_ip in incoming_hashes and hash != get_md5(incoming_hashes[sender_ip]):
                print("Hash mismatch, beware man in the middle!")


        print(">>")

        # update the last hash
        incoming_hashes[sender_ip] = hash


def message_interface():
    print_online_users()
    print("Enter the username: (-1 to menu)" )
    username = input(">>").lower()

    if username == "-1":
        return
    elif username in online_users:
        print("Enter the message: (-1 to menu)")
        message = input(">>")
        if message == "-1":
            return
        else:
            try:
                send_message(online_users[username], message)
            except:
                print("User {0} seems to be offline. Please try again.".format(username))


    else:
        print("User '{}' not found. Try discovering online users.".format(username))
        message_interface()


def file_interface():
    print_online_users()
    print("Enter the filename: (-1 to menu)")
    filename = input(">>").lower()

    if filename == "-1":
        return

    torrent.get_file(filename)


# Sends a message to an ip address. If it is first message to that user, hash is md5 digest of the message.
# Otherwise, it is md5 digest of the last incoming message hash from that user.
def send_message(ip_addr, message):
    hash = get_md5(message)
    if ip_addr in incoming_hashes:
        hash = get_md5(incoming_hashes[ip_addr])

    # message packet format -> sourceIP;hash;message;
    packet = "{0};{1};{2}".format(get_own_ip(), hash, message)
    send_tcp_packet(ip_addr, MESSAGE_PORT, packet, 3)

    # Update the last hash
    sent_hashes[ip_addr] = hash


def print_menu():
    print("Please Enter: ")
    print(" 1. Who is online?")
    print(" 2. Discover people!")
    print(" 3. Message to someone")
    print(" 4. List available files")
    print(" 5. Get a file")
    print(" 6. Exit")


if __name__ == "__main__":

    # Daemon threads for listening discovery and message packets
    threading.Thread(target=listen_tcp_discovery_packets, daemon=True).start()
    threading.Thread(target=listen_udp_discovery_packets, daemon=True).start()

    threading.Thread(target=listen_message_packets, daemon=True).start()
    threading.Thread(target=broadcast_continuously, daemon=True).start()

    torrent.start()

    while True:
        print_menu()
        choice = input(">>")
        if choice == "1":
            print_online_users()
        elif choice == "2":
            discover()
        elif choice == "3":
            message_interface()
        elif choice == "4":
            torrent.list_available_files()
        elif choice == "5":
            file_interface()
        elif choice == "6":
            print("bye")
            exit(0)
        else:
            print("Wrong choice!")