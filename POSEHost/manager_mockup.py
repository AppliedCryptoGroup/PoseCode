from typing import List
import traceback

from web3 import Web3
from solcx import compile_source, set_solc_version_pragma
from eth_abi import encode_abi
from eth_account import messages

# Mockup class for local testing of POSE enclaves

set_solc_version_pragma('0.6.1')

# config
contract_address = '0x27d160115a1E2aA7C4F709dDEB9dABbA82Ba5188'
account_address = '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1'
sol_file = 'PoseManager_ECDSA.sol'
w3_address = 'http://0.0.0.0:0000'

# init
w3 = None
manager = None
def init():
    tmp = 123


def register_enclave(addr: bytes, epk: bytes, esig: bytes):
    print('register_enclave called')
    return 0


def init_creation(addr: bytes, code_hash: bytes, contract_id: int):
    print('init_creation called')
    return 0


def finalize_creation(contract_id: int, pool_addr: bytes, pool_ops: List[bytes], esig: bytes):
    print('finalize_creation called')
    return 0


def finalize_creation_encoding(contract_id: int, pool_addr: bytes, pool_ops: List[bytes], cp_hash:bytes, code_hash: bytes):
    print('finalize_creation called')
    return 0


def get_operator_list():
    print('get_operator_list called')
    result = [Web3.toBytes(hexstr='0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1'),
              Web3.toBytes(hexstr='0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0'),
              Web3.toBytes(hexstr='0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b')]
    return result


def get_event_txs_since(contract_id: int, block_no: int):
    print('get_event_txs_since called')
    print(f'contract_id: {contract_id}')
    return [[], [], [], []]  # not relevant anymore, see encoded version


# same as above, but returns already encoded data
def get_event_txs_since_encoded(contract_id: int, block_no: int):
    print('get_event_txs_since_encoded called')
    print(f'contract_id: {contract_id}')
    print(f'resulting CP should be: 0x0ef813c8fe6c25ee77cd4ac10b4928151695a894121ee3ddbee692891d4a2cd6')
    result = [Web3.toBytes(hexstr='000000000000000000000000000000000000000000000000000000000000008000000000000000000000000090f8bf6a479f320ead074411a4b0e7944ea8c9c10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006453c81db600000000000000000000000090f8bf6a479f320ead074411a4b0e7944ea8c9c1290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000'),
              Web3.toBytes(hexstr='000000000000000000000000000000000000000000000000000000000000008000000000000000000000000090f8bf6a479f320ead074411a4b0e7944ea8c9c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000124786cd4d700000000000000000000000090f8bf6a479f320ead074411a4b0e7944ea8c9c1000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000001bfc6070de4a0753cff0f2d7736e367f8726fddb1307f8be1845f5d90228dcaca947dec8d9208ad6acfa1afe92f56bc65636a862cc1183233070f1626d412587d200000000000000000000000000000000000000000000000000000000')]
    return result

