#########################################################################
# Richie Harris
# rkharris12@gmail.com
# 5/23/2021
#########################################################################

# functions to build a merkle tree and find a merkle root

import hashlib, math


def reverse_byte_order(hex_str): 
    '''reverse the order of bytes in a hex string'''

    return ''.join([ hex_str[2 * i: 2 * i + 2] for i in list(range(0, len(hex_str) // 2))[::-1] ])


def reverse_word_order(hex_str):
    '''reverse the order of 32 bit words in a hex string'''

    return ''.join([ hex_str[8 * i: 8 * i + 8] for i in list(range(0, len(hex_str) // 8))[::-1] ])


def sha256d(message):
  '''Double SHA256 Hashing function.'''

  return hashlib.sha256(hashlib.sha256(message).digest()).digest()


def merkle_root_tree_bin(coinbase, merkle_tree):
    '''Builds a merkle root from the merkle tree'''

    coinbase_bin = bytes.fromhex(coinbase)
    coinbase_hash_bin = sha256d(coinbase_bin)

    merkle_root_tree_bin = coinbase_hash_bin
    for branch in merkle_tree:
        merkle_root_tree_bin = sha256d(merkle_root_tree_bin + bytes.fromhex(branch))
    return merkle_root_tree_bin


def merkle_root_txids_bin(txids_bin):
    '''Builds a merkle root from a list of transactions'''

    if len(txids_bin) <= 1:
        return txids_bin[0]
    else:
        merkle_level = []
        for i in range(0, len(txids_bin)-1, 2):
            merkle_level.append(sha256d(txids_bin[i]+txids_bin[i+1]))
        if len(txids_bin) % 2 == 1:
            merkle_level.append(sha256d(txids_bin[-1]+txids_bin[-1]))
        return merkle_root_txids_bin(merkle_level)


def merkle_tree(txids_bin):
    '''Computes merkle branches from nonempty list of transactions not including coinbase'''

    num_branches = int(math.ceil(math.log(len(txids_bin), 2)))
    txids_range = 2
    merkle_tree = [txids_bin[1].hex()]
    for i in range(num_branches-1):
        merkle_tree.append(merkle_root_txids_bin(txids_bin[txids_range:(2*txids_range)]).hex())
        txids_range *= 2

    return merkle_tree


# setup from bitcoin block 123,456
coinbase = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704b3936a1a017cffffffff01403d522a01000000434104563053b8900762f3d3e8725012d617d177e3c4af3275c3265a1908b434e0df91ec75603d0d8955ef040e5f68d5c36989efe21a59f4ef94a5cc95c99794a84492ac00000000"
tx1 = "e3d0425ab346dd5b76f44c222a4bb5d16640a4247050ef82462ab17e229c83b4"
tx2 = "137d247eca8b99dee58e1e9232014183a5c5a9e338001a0109df32794cdcc92e"
tx3 = "5fd167f7b8c417e59106ef5acfe181b09d71b8353a61a55a2f01aa266af5412d"
tx4 = "60925f1948b71f429d514ead7ae7391e0edf965bf5a60331398dae24c6964774"
tx5 = "d4d5fc1529487527e9873256934dfb1e4cdcb39f4c0509577ca19bfad6c5d28f"
tx6 = "7b29d65e5018c56a33652085dbb13f2df39a1a9942bfe1f7e78e97919a6bdea2"
tx7 = "0b89e120efd0a4674c127a76ff5f7590ca304e6a064fbc51adffbd7ce3a3deef"
tx8 = "603f2044da9656084174cfb5812feaf510f862d3addcf70cacce3dc55dab446e"
tx9 = "9a4ed892b43a4df916a7a1213b78e83cd83f5695f635d535c94b2b65ffb144d3"
tx10 = "dda726e3dad9504dce5098dfab5064ecd4a7650bfe854bb2606da3152b60e427"
tx11 = "e46ea8b4d68719b65ead930f07f1f3804cb3701014f8e6d76c4bdbc390893b94"
tx12 = "864a102aeedf53dd9b2baab4eeb898c5083fde6141113e0606b664c41fe15e1f"
txids = [reverse_byte_order(sha256d(bytes.fromhex(coinbase)).hex()), tx1, tx2, tx3, tx4, tx5, tx6, tx7, tx8, tx9, tx10, tx11, tx12]
txids_bin = []
for i, txid in enumerate(txids):
    txids_bin.append(bytes.fromhex(reverse_byte_order(txid)))

# merkle root from TX IDs
merkle_root_bin = merkle_root_txids_bin(txids_bin)
merkle_root_rev = merkle_root_bin.hex()
merkle_root = reverse_byte_order(merkle_root_rev)
print("merkle root from TXIDs: %s" % merkle_root)

# merkle root from merkle tree
merkle_tree = merkle_tree(txids_bin)
print("merkle tree:")
print(merkle_tree)
merkle_root_bin = merkle_root_tree_bin(coinbase, merkle_tree)
merkle_root_rev = merkle_root_bin.hex()
merkle_root = reverse_byte_order(merkle_root_rev)
print("merkle root from merkle tree: %s" % merkle_root)
