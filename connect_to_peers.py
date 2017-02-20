import socket
import struct
import time
import hashlib
# use a dns request to a seed bitcoin DNS server to find a node
nodes = socket.getaddrinfo("seed.bitcoin.sipa.be", None)

# arbitrarily choose the first node
node = nodes[0][4][0]

print(node)

#node = "213.239.201.46"

# https://bitcoin.org/en/developer-reference#verack
version = 70014
services = 0 # not a full node, cant provide any data
timestamp = int(time.time())
addr_recvservices = 0
addr_recvipaddress = socket.inet_pton(socket.AF_INET6, "::ffff:127.0.0.1") #ip address of receiving node in big endian
addr_recvport = 8333
addr_transservices = 0
addr_transipaddress = socket.inet_pton(socket.AF_INET6, "::ffff:127.0.0.1")
addr_transport = 8333
nonce = 0
user_agentbytes = 0
start_height = 329167
relay = 0

# 4 bytes = I
# 8 bytes = Q
# 2 bytes = H

# cant seem to specify endianess for each field separately
header = struct.pack(">L", 4190024921)
header += struct.pack("12s", bytes("version", 'utf-8'))
header += struct.pack("<L", 86)

message = struct.pack("<I", version)
message += struct.pack("<Q", services)
message += struct.pack("<Q", timestamp)
message += struct.pack("<Q", addr_recvservices)
message += struct.pack("16s", addr_recvipaddress)
message += struct.pack(">H", addr_recvport)
message += struct.pack("<Q", addr_transservices)
message += struct.pack("16s", addr_transipaddress)
message += struct.pack(">H", addr_transport)
message += struct.pack("<Q", nonce)
message += struct.pack("<H", user_agentbytes)
message += struct.pack("<I", start_height)

header += hashlib.sha256(hashlib.sha256(message).digest()).digest()[:4]

print(message.hex())

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node, 8333))
s.send(header + message)
s.recv(1024)

"""
72110100 ........................... Protocol version: 70002
0100000000000000 ................... Services: NODE_NETWORK 
bc8f5e5400000000 ................... Epoch time: 1415483324

0100000000000000 ................... Receiving node's services
00000000000000000000ffffc61b6409 ... Receiving node's IPv6 address
208d ............................... Receiving node's port number

0100000000000000 ................... Transmitting node's services
00000000000000000000ffffcb0071c0 ... Transmitting node's IPv6 address
208d ............................... Transmitting node's port number

128035cbc97953f8 ................... Nonce

0f ................................. Bytes in user agent string: 15
2f5361746f7368693a302e392e332f ..... User agent: /Satoshi:0.9.2.1/

cf050500 ........................... Start height: 329167
01 ................................. Relay flag: true
"""

#https://github.com/shirriff/bitcoin-code/blob/master/utils.py