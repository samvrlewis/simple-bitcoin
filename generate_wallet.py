from ecdsa import SigningKey, SECP256k1
import random
import struct
import hashlib
import requests

# 58 character alphabet used
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(version, payload):
    """
    Gets a Base58Check string
    See https://en.bitcoin.it/wiki/Base58Check_encoding
    """
    version = bytes.fromhex(version)
    payload_enc = version + payload + hashlib.sha256(hashlib.sha256(version + payload).digest()).digest()[:4]
    result = int.from_bytes(payload_enc, byteorder="big")

    # count the leading 0s
    padding = len(payload_enc) - len(payload_enc.lstrip(b'\0'))
    encoded = []

    while result != 0:
        result, remainder = divmod(result, 58)
        encoded.append(alphabet[remainder])

    return padding*"1" + "".join(encoded)[::-1]

def get_public_address(private_address):
    # https://en.bitcoin.it/wiki/Protocol_documentation
    key_int = int(private_address, 16) 

    key = struct.pack(">Q", (key_int >> 192) & 0xFFFFFFFFFFFFFFFF)
    key += struct.pack(">Q", (key_int >> 128) & 0xFFFFFFFFFFFFFFFF)
    key += struct.pack(">Q", (key_int >> 64) & 0xFFFFFFFFFFFFFFFF)
    key += struct.pack(">Q", key_int & 0xFFFFFFFFFFFFFFFF)

    public_key = SigningKey.from_string(key, curve=SECP256k1).verifying_key.to_string()
    public_key = b"\04" + public_key
    
    hashed = hashlib.sha256(public_key).digest()

    h = hashlib.new('ripemd160') #uses openssl implementation
    h.update(hashed)
    ripehashed = h.digest()

    return ripehashed

print(base58_encode("00", get_public_address("0000123")))