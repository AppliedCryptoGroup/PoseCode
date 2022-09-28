from typing import List
import traceback

from web3 import Web3
from solcx import compile_source, set_solc_version_pragma
from eth_abi import encode_abi
from eth_account import messages

# Class abstracting Manager calls

set_solc_version_pragma('0.6.1')

# config
contract_address = '0x27d160115a1E2aA7C4F709dDEB9dABbA82Ba5188'  # fill in actual contract address (is printed after truffle migration)
account_address = '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1'  # take valid account with funds
creator_privkey = Web3.toBytes(hexstr='0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d')  # above account's private key
sol_file = 'PoseManager_ECDSA.sol'
w3_address = 'http://0.0.0.0:0000'


# init
w3 = None
manager = None
def init():
    global w3
    global manager
    w3 = Web3(Web3.HTTPProvider(w3_address))
    with open(sol_file, 'r') as f:
        source = f.read()

    compiled_sol = compile_source(source)
    contract_id, contract_interface = compiled_sol.popitem()
    manager = w3.eth.contract(address=contract_address, abi=contract_interface["abi"])


def register_enclave(addr: bytes, epk: bytes, esig: bytes):
    print('register_enclave called')
    try:
        # convert to ethereum readable hex
        ex_addr = Web3.toChecksumAddress(addr)
        print(f'addr: {ex_addr}')
        ex_epk = Web3.toHex(epk)
        print(f'epk: {ex_epk}')
        ex_esig = Web3.toHex(esig)
        print(f'esig: {ex_esig}')

        # WITHOUT gas (only simulates if successful):
        # result = manager.functions.register(ex_addr, ex_epk, ex_esig).call()
        # print(result)
        # WITH gas (actual execution):
        tx_hash = manager.functions.register(ex_addr, ex_epk, ex_esig).transact({'from': account_address})
        receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        print(f'tx receipt: {dict(receipt)}')
        print(f'tx success: {receipt["status"]}')
    except:
        traceback.print_exc()
        return -1
    return 0


def init_creation(addr: bytes, code_hash: bytes, contract_id: int):
    print('init_creation called')
    try:
        ex_addr = Web3.toChecksumAddress(addr)
        print(f'addr: {ex_addr}')
        ex_code_hash = Web3.toHex(code_hash)
        print(f'code_hash: {ex_code_hash}')

        # WITHOUT gas (only simulates if successful):
        # result = manager.functions.initCreation(ex_addr, ex_code_hash, contract_id).call()
        # print(result)
        # WITH gas (actual execution):
        tx_hash = manager.functions.initCreation(ex_addr, ex_code_hash, contract_id).transact({'from': account_address})
        receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        print(f'tx receipt: {dict(receipt)}')
        print(f'tx success: {receipt["status"]}')
    except:
        traceback.print_exc()
        return -1
    return 0


def finalize_creation(contract_id: int, pool_addr: bytes, pool_ops: List[bytes], esig: bytes):
    print('finalize_creation called')
    try:
        ex_pool_addr = Web3.toChecksumAddress(pool_addr)
        print(f'pool_addr: {ex_pool_addr}')
        ex_pool_ops = []
        for o in pool_ops:
            ex_pool_ops.append(Web3.toChecksumAddress(o))
        print(f'pool_ops: {ex_pool_ops}')
        ex_esig = Web3.toHex(esig)
        print(f'esig: {ex_esig}')

        # WITHOUT gas (only simulates if successful):
        # result = manager.functions.finalizeCreation(contract_id, ex_pool_addr, ex_pool_ops, ex_esig).call()
        # print(result)
        # WITH gas (actual execution):
        tx_hash = manager.functions.finalizeCreation(contract_id, ex_pool_addr, ex_pool_ops, ex_esig).transact({'from': account_address})
        receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        print(f'tx receipt: {dict(receipt)}')
        print(f'tx success: {receipt["status"]}')
    except:
        traceback.print_exc()
        return -1
    return 0


def finalize_creation_encoding(contract_id: int, pool_addr: bytes, pool_ops: List[bytes], cp_hash:bytes, code_hash: bytes):
    print('finalize_creation called')
    try:
        ex_pool_addr = Web3.toChecksumAddress(pool_addr)
        print(f'pool_addr: {ex_pool_addr}')
        ex_pool_ops = []
        for o in pool_ops:
            ex_pool_ops.append(Web3.toChecksumAddress(o))
        print(f'pool_ops: {ex_pool_ops}')

        # create finalization signature
        finalization_hash = Web3.keccak(encode_abi(['string', 'uint', 'bytes32', 'address', 'bytes32', 'address[3]'],
                                                   ['Creation-Attest', contract_id, cp_hash, pool_addr, code_hash,
                                                    pool_ops]))
        challenge_msg = messages.encode_defunct(finalization_hash)
        sig = w3.eth.account.sign_message(challenge_msg, creator_privkey)
        encoded_sig = encode_abi(['uint8', 'bytes32', 'bytes32'], [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
        print(f'encoded_sig: {encoded_sig}')

        tx_hash = manager.functions.finalizeCreation(contract_id, ex_pool_addr, ex_pool_ops, encoded_sig).transact(
            {'from': account_address})
        receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        print(f'tx receipt: {dict(receipt)}')
        print(f'tx success: {receipt["status"]}')
    except:
        traceback.print_exc()
        return -1
    return 0


def get_operator_list():
    print('get_operator_list called')
    result = []
    i = 0
    try:  # when operator list has ended, will get exception (LOL)
        while True:
            result.append(Web3.toBytes(hexstr=manager.functions.operatorList(i).call()))
            i += 1
    finally:
        return result


def get_event_txs_since(contract_id: int, block_no: int):
    print('get_event_txs_since called')
    print(f'contract_id: {contract_id}')
    try:
        from_block = Web3.toHex(block_no)
        print(f'block_no: {from_block}')

        # get all events
        events = []
        transfer_filter = manager.events.NewOperator.createFilter(fromBlock=from_block)
        events.append(transfer_filter.get_all_entries())
        transfer_filter = manager.events.CreationInitialized.createFilter(fromBlock=from_block)
        events.append(transfer_filter.get_all_entries())
        transfer_filter = manager.events.ContractCreated.createFilter(fromBlock=from_block)
        events.append(transfer_filter.get_all_entries())

        # filter by contract and order events
        filtered_events = []
        for e in events:
            if not e:  # empty?
                continue
            e = e[0]  # ugly, but works ¯\_(ツ)_/¯
            if e['event'] == 'NewOperator' or int(e['args']['id']) == contract_id:
                index = 0
                for i in range(len(filtered_events)):
                    if int(e['blockNumber']) == int(filtered_events[i]['blockNumber']):
                        if int(e['transactionIndex']) > int(filtered_events[i]['transactionIndex']):
                            index = i
                    elif int(e['blockNumber']) > int(filtered_events[i]['blockNumber']):
                        index = i
                        break
                filtered_events = filtered_events[:index] + [e] + filtered_events[index:]

        # get tx data fields: txhash,  input, from,    value
        #                     bytes32, bytes, address, uint256
        hashes = []
        inputs = []
        froms = []
        values = []
        for e in filtered_events:
            txhash = e['transactionHash']
            txdata = w3.eth.getTransaction(txhash)
            hashes.append(Web3.toBytes(hexstr=txhash.hex()))
            inputs.append(Web3.toBytes(hexstr=txdata['input']))
            froms.append(Web3.toBytes(hexstr=txdata['from']))
            values.append(int(txdata['value']))

            print(f'txhash: {txhash.hex()}')
            print(f'input (len: {len(txdata["input"])}): {txdata["input"]}')
            print(f'from: {txdata["from"]}')
            print(f'value: {int(txdata["value"])}')
        result = []
        result.append(hashes)
        result.append(inputs)
        result.append(froms)
        result.append(values)
        # return [hashes, inputs, froms, values]  # returns array of arrays
        return result
    except:
        traceback.print_exc()
        return [[], [], [], []]


# same as above, but returns already encoded data (missing old incr hash!)
def get_event_txs_since_encoded(contract_id: int, block_no: int):
    print('get_event_txs_since_encoded called')
    print(f'contract_id: {contract_id}')
    try:
        from_block = Web3.toHex(block_no)
        print(f'block_no: {from_block}')

        # get all events
        events = []
        transfer_filter = manager.events.NewOperator.createFilter(fromBlock=from_block)
        events.append(transfer_filter.get_all_entries())
        transfer_filter = manager.events.CreationInitialized.createFilter(fromBlock=from_block)
        events.append(transfer_filter.get_all_entries())
        transfer_filter = manager.events.ContractCreated.createFilter(fromBlock=from_block)
        events.append(transfer_filter.get_all_entries())

        # filter by contract and order events
        filtered_events = []
        for e in events:
            if not e:  # empty?
                continue
            # UPDATED as not limited to contract id!
            e = e[0]  # ugly, but works ¯\_(ツ)_/¯
            index = 0
            for i in range(len(filtered_events)):
                if int(e['blockNumber']) == int(filtered_events[i]['blockNumber']):
                    if int(e['transactionIndex']) > int(filtered_events[i]['transactionIndex']):
                        index = i
                elif int(e['blockNumber']) > int(filtered_events[i]['blockNumber']):
                    index = i
                    break
            filtered_events = filtered_events[:index] + [e] + filtered_events[index:]

        # get tx data fields: input, from,    value
        #                     bytes, address, uint256
        encoded_result = []
        for e in filtered_events:
            txhash = e['transactionHash']
            txdata = w3.eth.getTransaction(txhash)
            input = Web3.toBytes(hexstr=txdata['input'])
            from_addr = Web3.toBytes(hexstr=txdata['from'])
            value = int(txdata['value'])

            rest = encode_abi(['bytes', 'address', 'uint256'], [input, from_addr, value])
            rest_ba = bytearray(rest)
            rest_ba[31] = 128  # mega cheat
            rest = bytes(rest_ba)
            print(f'encoded_rest: {rest.hex()}')
            encoded_result.append(rest)
        return encoded_result
    except:
        traceback.print_exc()
        return []

