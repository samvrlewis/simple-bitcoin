"""
useful resources:
    - https://en.bitcoin.it/wiki/Transaction
    - https://en.bitcoin.it/wiki/Raw_Transactions
    - http://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required
    - https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
    - https://coinb.in/#verify
    - https://blockchain.info/address/1KAWPAD8KovUo53pqHUY2bLNMTYa1obFX9
    - https://bitcoin.org/en/developer-reference#raw-transaction-format
    
- each transaction has at least one input and output
- output is an unspent transaction output until later spend
- output is number of satoshis
    - pays to conditional pubkey script
    - anyone who can satisfy the pubkey script can spend the satoshis
- input uses txid and output index num to specify an output to be spent
    - also has signature script which allows to satisfy pubkey script
- pay to public key has (p2pkh) is most common transaction type
- btc not redemeed in an output is considered to be tx fee
    - so need to be careful you spend all inputs!!!
- script:
    - input scriptsig (transmited by sender to prove it can spend outputs)
    evaluated first, then output scriptPubKey (sets conditions for output spending)
    - scriptPubKey uses value left on stack
    - if input authorized, scriptPubKey returns true

- signature script:
    - secp256k1 signature using private key + transaction data


"""
import struct

def publickey_to_pubscript(pub_key):
    """
    This is the standard 'pay to pubkey hash' script

    pub_key: Hex string of the public key
    """
    # OP_DUP then OP_HASH160 then 20 bytes
    script = bytes.fromhex("76a9")

    # The address to pay to
    script += bytes.fromhex(pub_key)

    # OP_EQUALVERIFY then OP_CHECKSIG
    script += bytes.fromhex("88ac")
    print(script.hex())

    return script

def make_raw_transaction(from_addr, to_addr, transaction_hash, output_index, satoshis_spend):
    #https://bitcoin.org/en/developer-reference#raw-transaction-format
    raw_transaction  = struct.pack("<L", 1) # version (always = 1)
    raw_transaction += struct.pack("<B", 1) # number of inputs

    # 'tx_in' structure
    #unknown why reversed: 
    ## https://bitcoin.org/en/developer-reference#hash-byte-order
    tx_in  = struct.pack("32s", bytes.fromhex(transaction_hash[::-1])) # txid in internal byte order
    tx_in += struct.pack("<L", output_index) # output to spend
    tx_in += struct.pack("<B", 25) # length of signature script
    tx_in += struct.pack("25s", publickey_to_pubscript(from_addr))
    tx_in += struct.pack("<L", 0xffffffff)
    raw_transaction += tx_in

    raw_transaction += struct.pack("<B", 1) # number of output

    # 'tx_out' struct
    tx_out  = struct.pack("<q", satoshis_spend) # number of satoshis to spend
    tx_out += struct.pack("<B", 25) # num bytes in script
    tx_out += struct.pack("25s", publickey_to_pubscript(to_addr)) 
    raw_transaction += tx_out

    raw_transaction += struct.pack("<L", 0) # transaction locktime
    raw_transaction += struct.pack("<L", 1) # hash code type

    return raw_transaction

import hashlib

trans_id = "eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2"[::-1]
from_addr = "14010966776006953d5567439e5e39f86a0d273bee"
to_addr = "14097072524438d003d23a2f23edb65aae1bb3e469"
satoshis = 99900000

raw = make_raw_transaction(from_addr, to_addr, trans_id, 1, satoshis)

print(raw)
print(hashlib.sha256(hashlib.sha256(raw).digest()).digest().hex())

"""
01000000
01
eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2
01000000
19
76a914010966776006953d5567439e5e39f86a0d273bee88ac
ffffffff
01
605af40500000000
19
76a914097072524438d003d23a2f23edb65aae1bb3e46988ac
00000000
01000000
"""