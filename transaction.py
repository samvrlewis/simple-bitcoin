import struct
import hashlib
from ecdsa import SigningKey, SECP256k1, util

import address_utils

def get_packed_transaction(transaction_dict):
    """
    Packs a dictionary with transaction data in accordance with Bitcoin's 
    transaction format:
    https://bitcoin.org/en/developer-reference#raw-transaction-format
    """
    raw_transaction  = struct.pack("<L", transaction_dict["version"])
    raw_transaction += struct.pack("<B", transaction_dict["num_inputs"])
    tx_in  = struct.pack("32s", transaction_dict["transaction_hash"])
    tx_in += struct.pack("<L", transaction_dict["output_index"]) 
    tx_in += struct.pack("<B", transaction_dict["sig_script_length"])
    tx_in += struct.pack(str(transaction_dict["sig_script_length"]) + "s", transaction_dict["sig_script"])
    tx_in += struct.pack("<L", transaction_dict["sequence"])
    
    raw_transaction += tx_in

    raw_transaction += struct.pack("<B", transaction_dict["num_outputs"]) 
    tx_out  = struct.pack("<q", transaction_dict["satoshis"])
    tx_out += struct.pack("<B", transaction_dict["pubkey_length"])
    tx_out += struct.pack("25s", transaction_dict["pubkey_script"]) 

    raw_transaction += tx_out
    raw_transaction += struct.pack("<L", transaction_dict["lock_time"])

    if "hash_code_type" in transaction_dict:
        raw_transaction += struct.pack("<L", transaction_dict["hash_code_type"])

    return raw_transaction

def get_p2pkh_script(pub_key):
    """
    This is the standard 'pay to pubkey hash' script
    """
    # OP_DUP then OP_HASH160 then 20 bytes (pub address length)
    script = bytes.fromhex("76a914")

    # The address to pay to
    script += pub_key

    # OP_EQUALVERIFY then OP_CHECKSIG
    script += bytes.fromhex("88ac")

    return script

def get_raw_transaction(from_addr, to_addr, transaction_hash, output_index, satoshis_spend):
    transaction = {}
    transaction["version"] = 1
    transaction["num_inputs"] = 1

    # transaction byte order should be reversed:
    # https://bitcoin.org/en/developer-reference#hash-byte-order
    transaction["transaction_hash"] = bytes.fromhex(transaction_hash)[::-1]
    transaction["output_index"] = output_index

    # temporarily make the signature script the old pubkey script
    # this will later be replaced. I'm assuming here that the previous
    # pubkey script was a p2pkh script here
    transaction["sig_script_length"] = 25
    transaction["sig_script"] = get_p2pkh_script(from_addr)

    transaction["sequence"] = 0xffffffff
    transaction["num_outputs"] = 1
    transaction["satoshis"] = satoshis_spend
    transaction["pubkey_length"] = 25
    transaction["pubkey_script"] = get_p2pkh_script(to_addr)
    transaction["lock_time"] = 0
    transaction["hash_code_type"] = 1

    return transaction

def get_transaction_signature(transaction, private_key):
    """
    Gets the sigscript of a raw transaction
    private_key should be in bytes form
    """
    packed_raw_transaction = get_packed_transaction(transaction)
    hash = hashlib.sha256(hashlib.sha256(packed_raw_transaction).digest()).digest()
    public_key = address_utils.get_public_key(private_key)
    key = SigningKey.from_string(private_key, curve=SECP256k1)
    signature = key.sign_digest(hash, sigencode=util.sigencode_der)
    signature += b'01' #hash code type

    sigscript = struct.pack("<B", len(signature))
    sigscript += signature
    sigscript += struct.pack("<B", len(public_key))
    sigscript += public_key

    return sigscript

def get_signed_transaction(from_addr, from_private_key, to_addr, transaction_hash, output_index, satoshis):
    """
    Returns a packed signed transaction, ready for transmission to the network
    """
    raw = get_raw_transaction(from_addr, to_addr, transaction_hash, output_index, satoshis)
    signature = get_transaction_signature(raw, from_private_key)
    
    raw["sig_script_length"] = len(signature)
    raw["sig_script"] = signature
    del raw["hash_code_type"]

    return get_packed_transaction(raw)

if __name__ == "__main__":
    private_key = address_utils.get_private_key("1234")
    public_key = address_utils.get_public_key(private_key)
    public_address = address_utils.get_public_address(public_key)
    to_address = address_utils.get_public_address(address_utils.get_public_key(address_utils.get_private_key("BADCAFEFABC0FFEE")))
    transaction_id = "95855ba9f46c6936d7b5ee6733c81e715ac92199938ce30ac3e1214b8c2cd8d7"
    satoshis = 400000
    output_index = 1

    transaction = get_signed_transaction(
        public_address, 
        private_key, 
        to_address, 
        transaction_id, 
        output_index, 
        satoshis)

    print(transaction.hex())