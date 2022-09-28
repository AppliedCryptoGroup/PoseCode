import time
import sys
from web3 import Web3
from solcx import compile_source, set_solc_version_pragma
from eth_abi import encode_abi
from eth_account import messages

set_solc_version_pragma('0.6.1')

contract_address = '0x27d160115a1E2aA7C4F709dDEB9dABbA82Ba5188'  # fill in actual contract address (is printed after truffle migration)
sol_file = 'PoseManager_ECDSA.sol'
w3_address = 'http://0.0.0.0:0000'

w3 = Web3(Web3.HTTPProvider(w3_address))

with open(sol_file, 'r') as f:
    source = f.read()
compiled_sol = compile_source(source)
contract_id_sol, contract_interface = compiled_sol.popitem()
contract = w3.eth.contract(address=contract_address, abi=contract_interface["abi"])

# attestation authority
priv_key = Web3.toBytes(hexstr='0xb0057716d5917badaf911b193b12b910811c1497b5bada8d7711f758981c3773')
# operator pool
tee1_addr = Web3.toChecksumAddress('0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1')
tee2_addr = Web3.toChecksumAddress('0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0')
tee3_addr = Web3.toChecksumAddress('0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b')
tee1_priv_key = Web3.toBytes(hexstr='0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d')
tee2_priv_key = Web3.toBytes(hexstr='0x6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1')
tee3_priv_key = Web3.toBytes(hexstr='0x6370fd033278c143179d81c5526140625662b8daa446c22ee2d73db3707e620c')



##### register TEEs
print('##### register(address teeSignatureAddress, bytes memory teeEncryptionKey, bytes memory attestationSignature)')
### TEE 1
# calc attestation hash
att_hash = Web3.keccak(encode_abi(['string', 'bytes32', 'address', 'bytes'],
            ['Furious-Attest',
             Web3.toBytes(hexstr='0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563'),
             tee1_addr,
             Web3.toBytes(hexstr='0x00')]))
print(f'TEE 1 att_hash: {att_hash.hex()}')

# sign by authority
message = messages.encode_defunct(att_hash) 
sig = w3.eth.account.sign_message(message, priv_key)
encoded_sig = encode_abi(["uint8","bytes32","bytes32"],
                         [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
print(f'TEE 1 encoded_sig: {encoded_sig.hex()}')

# send out registration tx to solidity contract
tx_hash = contract.functions.register(tee1_addr, "0x00", encoded_sig).transact({'from': tee1_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'TEE 1 tx receipt: {dict(receipt)}')
print(f'TEE 1 tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')

### TEE 2
# calc attestation hash
att_hash = Web3.keccak(encode_abi(['string', 'bytes32', 'address', 'bytes'],
            ['Furious-Attest',
             Web3.toBytes(hexstr='0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563'),
             tee2_addr,
             Web3.toBytes(hexstr='0x00')]))
print(f'TEE 2 att_hash: {att_hash.hex()}')

# sign by authority
message = messages.encode_defunct(att_hash) 
sig = w3.eth.account.sign_message(message, priv_key)
encoded_sig = encode_abi(["uint8","bytes32","bytes32"],
                         [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
print(f'TEE 2 encoded_sig: {encoded_sig.hex()}')

# send out registration tx to solidity contract
tx_hash = contract.functions.register(tee2_addr, "0x00", encoded_sig).transact({'from': tee2_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'TEE 2 tx receipt: {dict(receipt)}')
print(f'TEE 2 tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')

### TEE 3
# calc attestation hash
att_hash = Web3.keccak(encode_abi(['string', 'bytes32', 'address', 'bytes'],
            ['Furious-Attest',
             Web3.toBytes(hexstr='0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563'),
             tee3_addr,
             Web3.toBytes(hexstr='0x00')]))
print(f'TEE 3 att_hash: {att_hash.hex()}')

# sign by authority
message = messages.encode_defunct(att_hash)
sig = w3.eth.account.sign_message(message, priv_key)
encoded_sig = encode_abi(["uint8","bytes32","bytes32"],
                         [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
print(f'TEE 3 encoded_sig: {encoded_sig.hex()}')

# send out registration tx to solidity contract
tx_hash = contract.functions.register(tee3_addr, "0x00", encoded_sig).transact({'from': tee3_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'TEE 3 tx receipt: {dict(receipt)}')
print(f'TEE 3 tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')



##### create contract
contract_id = 123
creator_addr = Web3.toChecksumAddress('0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1')
creator_privkey = Web3.toBytes(hexstr='0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d')
code_hash = Web3.toBytes(hexstr='0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563')
pool_addr = Web3.toChecksumAddress('0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d')
pool_ops = [tee1_addr, tee2_addr, tee3_addr]

print('##### initCreation(address creationOperator, bytes32 codeHash, uint freeId)')
tx_hash = contract.functions.initCreation(creator_addr, code_hash, contract_id).transact({'from': creator_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

### challenge watchdog
print('##### challangeWatchdogsDuringCreation(uint id, address[POOL_SIZE] memory pool_operators, bytes memory message, '
      'uint[POOL_SIZE] memory challangedOperators)')
challenge_msg = Web3.toBytes(hexstr='0x0102030405060708')
challenged = [0, 0, 1]  # challenge TEE 3
tx_hash = contract.functions.challengeWatchdogsDuringCreation(contract_id, pool_ops, challenge_msg, challenged)\
    .transact({'from': creator_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

print('##### watchdogResponse(uint id, uint index, bytes memory response, bytes memory signature)')
# watchdogResponse works for both challenges; message is arbitrary
response_msg = Web3.toBytes(hexstr='0x0a0b0c0d0e0f')
result = contract.functions.contracts(contract_id).call()
cp_hash = result[1]  # get incrementalTxHash
# signature
resp_hash = Web3.keccak(encode_abi(['string', 'uint', 'bytes32', 'bytes'],
                                   ['Watchdog-challenge-Response', contract_id, cp_hash, response_msg]))
resp_msg = messages.encode_defunct(resp_hash)
sig = w3.eth.account.sign_message(resp_msg, tee3_priv_key)
encoded_sig = encode_abi(['uint8', 'bytes32', 'bytes32'], [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
# execute call
tx_hash = contract.functions.watchdogResponse(contract_id, 2, response_msg, encoded_sig).transact({'from': tee3_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

# wait for timeout (>15s)
time.sleep(16)

print('##### watchdogFinalization(uint id)')
tx_hash = contract.functions.watchdogFinalization(contract_id).transact({'from': tee1_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

print('##### finalizeCreation(uint id, address payable pool_address, address[POOL_SIZE] memory pool_operators, '
      'bytes memory signature)')
# get current incrementalHash
result = contract.functions.contracts(contract_id).call()
cp_hash = result[1]
# create finalization signature
finalization_hash = Web3.keccak(encode_abi(['string', 'uint', 'bytes32', 'address', 'bytes32', 'address[3]'],
                                           ['Creation-Attest', contract_id, cp_hash, pool_addr, code_hash, pool_ops]))
challenge_msg = messages.encode_defunct(finalization_hash)
sig = w3.eth.account.sign_message(challenge_msg, creator_privkey)
encoded_sig = encode_abi(['uint8', 'bytes32', 'bytes32'], [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
# execute call
tx_hash = contract.functions.finalizeCreation(contract_id, pool_addr, pool_ops, encoded_sig)\
    .transact({'from': creator_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')



##### deposit
client_addr = Web3.toChecksumAddress('0xd03ea8624C8C5987235048901fB614fDcA89b117')
challenge_msg = Web3.toBytes(hexstr='0x0102030405060708')
response_msg = Web3.toBytes(hexstr='0x0a0b0c0d0e0f')

print('##### depositToContract(uint id)')
tx_hash = contract.functions.depositToContract(contract_id).transact({'from': client_addr, 'value': 10000000000000000})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')

print('##### withdraw(uint id, uint blocknumber, address payable receiver)')
tx_hash = contract.functions.withdraw(contract_id, 0, client_addr)\
    .transact({'from': pool_addr, 'value': 10000000000000000})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')

### challenge executor
print('##### challengeExecutor(uint id, bytes memory message)')
tx_hash = contract.functions.challengeExecutor(contract_id, challenge_msg).transact({'from': client_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

print('##### executorResponse(uint id, bytes memory response, bytes memory signature)')
# get current incrementalHash
result = contract.functions.contracts(contract_id).call()
cp_hash = result[1]
print(f'CP: {cp_hash.hex()}')
sig_hash = Web3.keccak(encode_abi(['string', 'uint', 'bytes32', 'bytes'],
                                  ['Challenge-Response', contract_id, cp_hash, response_msg]))
sig_msg = messages.encode_defunct(sig_hash)
sig = w3.eth.account.sign_message(sig_msg, tee1_priv_key)
encoded_sig = encode_abi(['uint8', 'bytes32', 'bytes32'], [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
tx_hash = contract.functions.executorResponse(contract_id, response_msg, encoded_sig).transact({'from': tee1_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

### challenge watchdog
print('##### challengeWatchdog(uint id, bytes memory message, uint8[POOL_SIZE] memory challangedOperators)')
challenged = [0, 0, 1]  # challenge TEE 3
tx_hash = contract.functions.challengeWatchdog(contract_id, challenge_msg, challenged).transact({'from': tee1_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

print('##### watchdogResponse(uint id, uint index, bytes memory response, bytes memory signature)')
# get current incrementalHash
result = contract.functions.contracts(contract_id).call()
cp_hash = result[1]
print(f'CP: {cp_hash.hex()}')
sig_hash = Web3.keccak(encode_abi(['string', 'uint', 'bytes32', 'bytes'],
                                  ['Watchdog-challenge-Response', contract_id, cp_hash, response_msg]))
sig_msg = messages.encode_defunct(sig_hash)
sig = w3.eth.account.sign_message(sig_msg, tee3_priv_key)
encoded_sig = encode_abi(['uint8', 'bytes32', 'bytes32'], [sig.v, Web3.toBytes(sig.r), Web3.toBytes(sig.s)])
tx_hash = contract.functions.watchdogResponse(contract_id, 2, response_msg, encoded_sig).transact({'from': tee3_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

# wait for timeout (>15s)
time.sleep(16)

print('##### watchdogFinalization(uint id)')
tx_hash = contract.functions.watchdogFinalization(contract_id).transact({'from': tee1_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')



##### challenge timeouts
challenge_msg = Web3.toBytes(hexstr='0xff02030405060708')
### watchdog
print('##### PREPARE: challengeWatchdog(uint id, bytes memory message, uint8[POOL_SIZE] memory challangedOperators)')
challenged = [0, 0, 1]  # challenge TEE 3
tx_hash = contract.functions.challengeWatchdog(contract_id, challenge_msg, challenged).transact({'from': tee1_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

# wait for timeout (>15s)
time.sleep(16)

print('##### watchdogFinalization(uint id)')
tx_hash = contract.functions.watchdogFinalization(contract_id).transact({'from': tee1_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

### executor
print('##### PREPARE: challengeExecutor(uint id, bytes memory message)')
tx_hash = contract.functions.challengeExecutor(contract_id, challenge_msg).transact({'from': client_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')

# wait for timeout (>15s)
time.sleep(16)

print('##### executorTimeout(uint id)')
tx_hash = contract.functions.executorTimeout(contract_id).transact({'from': client_addr})
receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f'tx receipt: {dict(receipt)}')
print(f'tx success: {receipt["status"]}')
print(f'tx gas used: {receipt["gasUsed"]}')
result = contract.functions.contracts(contract_id).call()
print(f'contract phase: {result[0]}')
