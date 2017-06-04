import socket
import struct
import time
import hashlib

def get_bitcoin_peer():
    # use a dns request to a seed bitcoin DNS server to find a node
    nodes = socket.getaddrinfo("seed.bitcoin.sipa.be", None)

    # arbitrarily choose the first node
    return nodes[0][4][0]

def get_bitcoin_message(message_type, payload):
    header = struct.pack(">L", 0xF9BEB4D9)
    header += struct.pack("12s", bytes(message_type, 'utf-8'))
    header += struct.pack("<L", len(payload))
    header += hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    return header + payload

def get_version_payload():
    version = 70014
    services = 1 # not a full node, cant provide any data
    timestamp = int(time.time())
    addr_recvservices = 1
    addr_recvipaddress = socket.inet_pton(socket.AF_INET6, "::ffff:127.0.0.1") #ip address of receiving node in big endian
    addr_recvport = 8333
    addr_transservices = 1
    addr_transipaddress = socket.inet_pton(socket.AF_INET6, "::ffff:127.0.0.1")
    addr_transport = 8333
    nonce = 0
    user_agentbytes = 0
    start_height = 329167
    relay = 0

    payload = struct.pack("<I", version)
    payload += struct.pack("<Q", services)
    payload += struct.pack("<Q", timestamp)
    payload += struct.pack("<Q", addr_recvservices)
    payload += struct.pack("16s", addr_recvipaddress)
    payload += struct.pack(">H", addr_recvport)
    payload += struct.pack("<Q", addr_transservices)
    payload += struct.pack("16s", addr_transipaddress)
    payload += struct.pack(">H", addr_transport)
    payload += struct.pack("<Q", nonce)
    payload += struct.pack("<H", user_agentbytes)
    payload += struct.pack("<I", start_height)

    return payload

def send_message(peer, message):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer, 8333))
    s.send(message)
    
    return s

if __name__ == "__main__":
    s = send_message(get_bitcoin_peer(), get_bitcoin_message("version", get_version_payload()))
    print(s.recv(3000))