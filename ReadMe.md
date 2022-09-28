# POSE: *P*ractical *O*ff-chain *S*mart Contract *E*xecution
This repository contains the prototype for the paper of the same name.

## Overview
- `SmartContract` contains the Solidity-based *Manager* contract.
- `POSEHost` contains the Python code to call the *Manager* contract as well as the C code to access the Python functionality on an enclave.
- The enclave code running Lua scripts will be included soon.

## Prerequisites for Ubuntu
- Ethereum testchain deployed, which can be on an external machine. We will refer to its IP and Port by <0.0.0.0:0000>
- Truffle installation:
	- Dependencies:  
    ```
	sudo apt-get -y install curl git vim build-essential
	```
	- NodeJS:  
	```
	curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
	sudo apt-get install -y nodejs
	```
	- Truffle:  
	```
	sudo npm install -g truffle
	```
- For `POSEhost` execute:
	- Have at least Python version 3.7 installed
	- Install dependency packages:  
	```
	pip install web3 py-solc py-solc-x eth-abi
	```
	- Install local solidity compiler version 0.6.1 by excuting in Python:
	```
	from solcx import install_solc
	install_solc('v0.6.1')
	```
	- Compile the C code in folder `POSEHost/Csrc` with the compiler flags provided by the commands:
	```
	python3-config --cflags
	python3-config --ldflags
	```
	- The Python files as well as the Solidity *Manager* file need to be placed in the execution directory of the binaries of the C-code

## Deploy
- Make sure the testchain is running
- If you want to deploy a new version just execute the command from the shell in the folder "SmartContract":
	```
	truffle migrate --reset
	```
- The last command will output the *Manager* contract address, which needs to be set in `POSEHost/manager.py`
- `POSEHost/fullManagerTest.py` tests all functionalities of the *Manager*
- If there are problems with re-deploying the contract, you may want to restart the testchain.
- If the testchain crashes execute and check:
	```
	nohup ganache-cli -d -h 0.0.0.0 > ganache.log &
	```
- Find some test accounts with funds, available after testchain setup are:
	```
	Public Accounts:

	(0) 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1 (100 ETH)
	(1) 0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0 (100 ETH)
	(2) 0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b (100 ETH)
	(3) 0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d (100 ETH)
	(4) 0xd03ea8624C8C5987235048901fB614fDcA89b117 (100 ETH)
	(5) 0x95cED938F7991cd0dFcb48F0a06a40FA1aF46EBC (100 ETH)
	(6) 0x3E5e9111Ae8eB78Fe1CC3bb8915d5D461F3Ef9A9 (100 ETH)
	(7) 0x28a8746e75304c0780E011BEd21C72cD78cd535E (100 ETH)
	(8) 0xACa94ef8bD5ffEE41947b4585a84BdA5a3d3DA6E (100 ETH)
	(9) 0x1dF62f291b2E969fB0849d99D9Ce41e2F137006e (100 ETH)

	Respective Private Keys:

	(0) 0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d
	(1) 0x6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1
	(2) 0x6370fd033278c143179d81c5526140625662b8daa446c22ee2d73db3707e620c
	(3) 0x646f1ce2fdad0e6deeeb5c7e8e5543bdde65e86029e2fd9fc169899c440a7913
	(4) 0xadd53f9a7e588d003326d1cbf9e4a43c061aadd9bc938c843a79e7b4fd2ad743
	(5) 0x395df67f0c2d2d9fe1ad08d1bc8b6627011959b79c53d7dd6a3536a33ab8a4fd
	(6) 0xe485d098507f54e7733a205420dfddbe58db035fa577fc294ebd14db90767a52
	(7) 0xa453611d9419d0e56f499079478fd72c37b251a94bfde4d19872c44cf65386e3
	(8) 0x829e924fdf021ba3dbbc4225edfece9aca04b929d6e75613329ca6f1d31c0bb4
	```
