/*
    Copyright (C) 2022  Authors of the POSE paper

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

pragma solidity ^0.6.1;
pragma experimental "ABIEncoderV2";

//The RSA-based version (attestation is performed via RSA signatures)
contract PoseManager_ECDSA {
    
    //Constants
    uint public constant POOL_SIZE = 3;
    uint public constant TIMEOUT_INTERVAL = 15;   //The maximal dispute time is 3 * TIMEOUT_INTERVAL
                                                  //because the executive operator can get "extra time" by challenging the watchdogs
    
    //For attestation
    //@ClientDeveloper: The WRAPPER_PROGRAM_CODE_HASH is currently a dummy value. Once, the client attestation allows
    //for configurable attestation implement it to sign hash("Pose-Attest" || hash(Enclave-Program) || Enclave Ethereum Address || Enclave Encryption Key)
    //and define WRAPPER_PROGRAM_CODE_HASH to equal hash(Pose-Program) such that it equals hash(Enclave-Program) if the enclave
    //installed the POSE Program
    bytes32 constant WRAPPER_PROGRAM_CODE_HASH = keccak256(abi.encode(0));                  //0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
     address public constant ATTESTATION_AUTHORITY = 0x1dF62f291b2E969fB0849d99D9Ce41e2F137006e;

    //Phases a contract can occupy
    enum Phase { NONE, CREATION, EXECUTING, CHALLENGE_EXECUTOR, CHALLENGE_WATCHDOG, CRASHED }
    
    //Events
    event NewOperator(address operator);
    event CreationInitialized(uint id);
    event ContractCreated(uint id, bytes txData);
    event ExecutorChallenged(uint id, bytes txData);
    event ExecutorResponse(uint id, bytes txData);
    event ExecutorKicked(uint id, bytes txData);
    event WatchdogChallenged(uint id, bytes txData);
    event WatchdogResponse(uint id, bytes txData);
    event WatchdogFinalized(uint id, bytes txData);
    event ContractCrashed(uint id);
    
    //@ClientDeveloper: How to use events and the tx-data information
    // - Use the operator to listen on all of the events
    //      - Use a web3j library for this, e.g. web3js
    // - When an event for a relevant id is registered do the following:
    // - Extract the information required from the txData field
    //       - This field contains all function parameters (you can e.g. use it to extract the challenge message, ...)
    // - Read the other relevant data from the contract (e.g., Who is the current executor). Same informaiton can be received from the TEE as well
    // - Always give the txData to the TEE
    // - TEE interprets the txData and learns what it should do
    //     - The txData contains the function that has been called, so the TEE knows how to interpret the txData
    //         - e.g., if it is a deposit the TEE needs to update the state
    //         - e.g., if it is a challenge the TEE needs to interpret the challenge message and answer it
    //         - ...
    //     - As the TEE can no longer access the on-chain state it needs to simulate the tx off-chain and evolve its off-chain state accordingly
    //          - e.g., kick inactive watchdogs, ...
    //     - This way the TEE can ensure that the local state and the on-chain state are always the same
    //          - You only need to simulate the state that is relevant for the TEE
    //          - You can for example ignore the timeout, because the TEE clock is not synchronized with the on-chain clock anyway
    // - The TEE updates it local incrementalTxHash which always needs to be the same as the on-chain one and need to be included into all signatures.
    //          - This way the Manager can ensure that the TEE is up-to-date
    //          - See modifier updateIncrementalTxHash to check how the incrementalTxHash is updated
    //- TxData has the following structure:
    //  - The first 4 bytes are the first 4 bytes of the hash of the method signature
    //      - These are used to determine the tx-type and thus to determine how to interpret the tx-data
    //      - In Solidity the method-hash would be calculated with: bytes4(keccak256(bytes(method-signature)));
    //          - Method signature are name and parameter-types without whitespaces and modifiers or location like "memory"
    //              - Signature of register: register(address,bytes,bytes)
    //              - Signature of initCreation: initCreation(address,bytes32,uint256)
    //              - ...
    //              - Sometimes types fo have synonyms: e.g. uint is actually uint256
    //              - Constants need t: uint256[POOL_SIZE] is actually uint256[30]
    //  - The other bytes are the abi-encoded function parameters
    //      - In solidity they would be equal to abi.encode(p1,p2,...);
    
    //Operator information 
    struct Operator {
        bool initialized;
        address teeSignatureAddress;
        bytes teeEncryptionKey;                     //If we use elliptic curve cryptography with 256-but curves, the public key is a point on that curve, and hence, 64 bytes of size.
    }
    
    //Contract information
    struct Contract {
        
        //General lifecycle management
        Phase phase;                                //Current phase
         bytes32 incrementalTxHash;                 //Incremental hash of all transactions relevant for this contract
                                                    //This is used as a checkpoint that enables a contract to check that the TEE is up-to-date
        
        //Contract and pool information
        address payable poolAddress;                // The address to the pool public key
        address creationOperator;                   // The address of the creation operator
        address[POOL_SIZE] operators;               // The operator pool, a kicked operator is one witha ddress(0)
        uint executiveOperator;                     // The index of the current executive operator within the operator pool
        bytes32 codeHash;                           // The code hash of the application logic
        
        //Dispute information
        Phase fallbackPhase;                        // A watchdog challenge can be within another challenge. Therefore we need to store the fallback phase after the watchdog challenge
        uint8 watchdogsChallenged;                   // Watchdogs may only be challenged once during an execution challenge. This variable helprs to ensure that
        bytes32 execChallengeHash;                  // The hash of the challenge message of the executor challenge
        bytes32 watchdogChallengeHash;              // The hash of the challengeHash of the watchdog challenge (we need both as watchdog challenge can be within executor challenge)
        uint8[POOL_SIZE] challengedWatchdogs;        // Array that stores which watchdogs are challenged
        uint deadline;
    }
    
    //Operator mapping
    mapping(address => Operator) public operators;
    address[] public operatorList;                  //To enable the client to iterate over all operators, if we wanted to save gas, we could also iterate over the past events
    bytes32 public operatorIncrementalHash = 0;                //The creaiton-TEE needs to sign the list of operators it receives to ensure that the input is correct
                                                    //However, encoding the whole list of operators to check the signed list hash can become really expensive
                                                    //Therefore we construct an incremental hash: newHash = hash(oldHash, new address); the initial hash is 0x00...00
                                                    //The downside is that the TEE has to calculate this incrementalHash when receiving a list of operators itself
    
    //Contract mapping
    mapping(uint => Contract) public contracts;
    
    //******************
    //Public functions

    
    //******************
    //Registration
    
    //Registers a Operator and attests TEE, there may only be one TEE per operator
    function register(address teeSignatureAddress, bytes memory teeEncryptionKey, bytes memory attestationSignature) public {
        
        //Check that operator has not registered another TEE
        require(operators[msg.sender].initialized == false, "The operator has already registered a TEE!");
        
        //Check the signature with the required signature algorithm //@ClientDeveloper: Here you can see what needs to be included into the attestation of a TEE  
        bytes32 attestationHash = keccak256(abi.encode("Pose-Attest", WRAPPER_PROGRAM_CODE_HASH, teeSignatureAddress, teeEncryptionKey));        //TODO: After the testing we should include the manager-address here as well: keccak256(abi.encode("Furious-Attest", WRAPPER_PROGRAM_CODE_HASH,  address(this), teeSignatureAddress, teeEncryptionKey)); 
        require(verifySignature(attestationHash, attestationSignature, ATTESTATION_AUTHORITY), "Wrong attestation");
        
        //Register operator
        operatorList.push(msg.sender);
        operators[msg.sender] = Operator(true, teeSignatureAddress, teeEncryptionKey);
        operatorIncrementalHash = keccak256(abi.encode(operatorIncrementalHash, msg.sender));
        
        //Notify clients
        emit NewOperator(msg.sender);
    }
    
    //******************
    //Creation
    
    //We do not challenge the creator. If he does not respond in time, the creation is simply not successful. Challenge would have the same effect.
    
    //Initializes the creation, we need this to ensure that the creation TEE gets the up-to-date state (e.g. list of operators) from the operator
    function initCreation(address creationOperator, bytes32 codeHash, uint freeId) public {
        
        //Checks
        require(contracts[freeId].phase == Phase.NONE, "Contract with this ID does already exist!");
        require(operators[creationOperator].initialized == true, "Creation operator does not exist!");
        
        //Creat contract Tuple
        address[POOL_SIZE] memory operatorArray;
        uint8[POOL_SIZE] memory challenged;
        contracts[freeId] = Contract(Phase.CREATION, operatorIncrementalHash, address(0), creationOperator, operatorArray, 0, codeHash, Phase.NONE, 0, 0, 0, challenged, now + TIMEOUT_INTERVAL);
        
        //Notify clients
        emit CreationInitialized(freeId);
    }
    
    //Enables the creation operator to challenge the pool during creation
    //Problem: During creation the TEEs do not receive the same message as they do not know the secret pool key
    //Solution: Simply interpret message as the concatination of all individual messages
    function challengeWatchdogsDuringCreation(uint id, address[POOL_SIZE] memory pool_operators, bytes memory message, uint8[POOL_SIZE] memory challengedOperators) public updateIncrementalTxHash(id, 0) {
        
        //Checks
        require(msg.sender == contracts[id].creationOperator, "Not the right account to challenge the watchdogs");                                                                                            
        require(contracts[id].phase == Phase.CREATION && contracts[id].watchdogsChallenged < 1, "Not the right phase to challenge watchdogs or watchdogs have already been challenged during creation!");
        
        //I think we can set this without a signature as it will be overwritten by a successful creation anyways
        contracts[id].operators = pool_operators;
        
        //Call the internal part of the watchdog challenge procedure (shared between watchdog challenges during execution and during creation)
        internalWatchdogChallenge(id, message, challengedOperators);
    }
    
    //Finalizes the creation. The TEE ensures that the values (e.g. Operator pool) are correct. We only need to check via the TEE-signature that it has received the correct inputs
    function finalizeCreation(uint id, address payable pool_address, address[POOL_SIZE] memory pool_operators, bytes memory signature) public updateIncrementalTxHash(id, 0){
        
        //Checks
        require(contracts[id].phase == Phase.CREATION, "The contract with this ID is not in the right phase to be created!");
        require(contracts[id].deadline >= now, "The creation deadline has expired!");
        
        //Check Signature //@ClientDeveloper: Here you can see what needs to be included into the creation finalization signature
        bytes32 signedHash = keccak256(abi.encode("Creation-Attest", id, contracts[id].incrementalTxHash, pool_address, contracts[id].codeHash, pool_operators));
        require(verifySignature(signedHash, signature, operators[contracts[id].creationOperator].teeSignatureAddress) == true, "Wrong signature for creation!");
        
        //Update state
        contracts[id].poolAddress = pool_address;
        contracts[id].phase = Phase.EXECUTING;
        contracts[id].operators = pool_operators;
        
        //Notify clients
        emit ContractCreated(id, msg.data);
    }
    
    //******************
    //Handling assets
    
    //Enables a party to deposit funds to a pool address, as we increment the checkpoint number this may only be done during phase executing
    function depositToContract(uint id) public payable updateIncrementalTxHash(id, msg.value){
        
        //You can only deposit to an executing contract
        require(contracts[id].phase == Phase.EXECUTING, "Contract with this ID is not in phase EXECUTING!");
        
        //Forward the money to the pool address
        contracts[id].poolAddress.transfer(msg.value);
    }
    
    //Enables a party to withdraw funds. The tx needs to be issued by the poolAddress (the pool-pk) and is broadcasted to the network by the client.
    //The tx contains the block number and block hash, when it was issued.
    //This way we ensure that the pool has been up-to-date with the blockchain when it has issued this payout. 
    function withdraw(uint id, uint blocknumber, address payable receiver) public payable updateIncrementalTxHash(id, msg.value) {
        
        //Checks
        require(msg.sender == contracts[id].poolAddress, "The sender of the payout tx is not the pool with the specified ID!");
        
        //Forwards the withdraw value to the receiver of the payout
        receiver.transfer(msg.value);
    }
    
    //******************
    //Execution Challenges - Can either be atomic (just challenge the executor) or combined with a challenge to the watchdogs by the executor. Needs to be complete before completing the challenge to the executor
    
    //Challenge the executor to provide the current state or execute a move (what exactly is encoded into the message)
    function challengeExecutor(uint id, bytes memory message) public updateIncrementalTxHash(id, 0) {
        
        //Checks
        require(contracts[id].phase == Phase.EXECUTING, "Can only challenge executor of contract in phase executing!");
        
        //Update state
        contracts[id].phase = Phase.CHALLENGE_EXECUTOR;
        contracts[id].deadline = now + TIMEOUT_INTERVAL;
        contracts[id].watchdogsChallenged = 0;
        contracts[id].execChallengeHash = keccak256(message);
        
        //Notify clients
        emit ExecutorChallenged(id, msg.data);
        
    }
    
    //Response of the executive operator
    function executorResponse(uint id, bytes memory response, bytes memory signature) public updateIncrementalTxHash(id, 0) {
        
        //Checks
        require(contracts[id].phase == Phase.CHALLENGE_EXECUTOR, "Challenge can only be answered if there is an unresolved challenge!");
        require(contracts[id].deadline >= now, "The response deadline has expired!");
        
        //Check Signature //@ClientDeveloper: Here you can see what needs to be included into the executor response signature
        bytes32 signedHash = keccak256(abi.encode("Challenge-Response", id, contracts[id].incrementalTxHash, response));  //Checkpoint-hash includes contracts[id].challengeHash
        require(verifySignature(signedHash, signature, operators[contracts[id].operators[contracts[id].executiveOperator]].teeSignatureAddress) == true, "Wrong signature for executor response!");
        
        //Update state
        contracts[id].phase = Phase.EXECUTING;
        
        //Notify clients
        emit ExecutorResponse(id, msg.data);
    }
    
    //Enables any party to kick the executive operator if it does not respond to a challenge in time
    function executorTimeout(uint id) public updateIncrementalTxHash(id, 0) {
        
        //Checks
        require(contracts[id].phase == Phase.CHALLENGE_EXECUTOR, "Challenge can only be timed out if there is an unresolved challenge!");
        require(contracts[id].deadline < now, "The response deadline has not expired!");
        
        //Drop the executor = Set his address to address(0)
        address _executor = contracts[id].operators[contracts[id].executiveOperator];
        contracts[id].operators[contracts[id].executiveOperator] = address(0);
        
        //Check if there is another active operator
        for(uint i = contracts[id].executiveOperator + 1; i < POOL_SIZE; i++) {
            if(contracts[id].operators[i] != address(0)){
                
                //Update state
                contracts[id].executiveOperator = i;
                contracts[id].phase = Phase.EXECUTING;
                
                //Notify clients
                emit ExecutorKicked(id, msg.data);
                
                return;
            }
        }
        
        //Otherwise: Mark the contract as crashed
        contracts[id].phase = Phase.CRASHED;
        
        //Notify clients
        emit ContractCrashed(id);

    }
    
    //********************
    // Challenge watchdogs
    
    //Enables the executors to challenge a list of watchdogs with a given message.
    //If their are individual messages for each watchdog, simply concatenate them to one 
    function challengeWatchdog(uint id, bytes memory message, uint8[POOL_SIZE] memory challengedOperators) public updateIncrementalTxHash(id, 0){
        
        //Checks
        require(msg.sender == contracts[id].operators[contracts[id].executiveOperator], "Not the right account to challenge the watchdogs");                                                                                            
        require(contracts[id].phase == Phase.EXECUTING || (contracts[id].phase == Phase.CHALLENGE_EXECUTOR && contracts[id].watchdogsChallenged < 2), "Not the right phase to challenge watchdogs or watchdogs have already been challenged within the same executor challenge!");   //Correct phase
        
        //Internal function to prevent duplicate code
        internalWatchdogChallenge(id, message, challengedOperators);
        
    }
    
    //Answers a watchdog challenge. The operator gives the challenge to the TEE which generates a response. The response can also be: <<Invalid Message>>
    //Id 1 is the index of the party in the operator-list, Id 2 is the index of the party in the challenged-list
    function watchdogResponse(uint id, uint index, bytes memory response, bytes memory signature) public updateIncrementalTxHash(id, 0) {
        
        //Checks
        require(contracts[id].phase == Phase.CHALLENGE_WATCHDOG, "Not the right phase to provude a watchdog response");
        require(contracts[id].deadline >= now, "The response deadline has expired!");
        
        //Verify signatures //@ClientDeveloper: Here you can see what needs to be included into a watchdog response signature
        bytes32 signedHash = keccak256(abi.encode("Watchdog-challenge-Response", id, contracts[id].incrementalTxHash, response));  //Checkpoint-hash includes contracts[id].challengeHash
        require(verifySignature(signedHash, signature, operators[contracts[id].operators[index]].teeSignatureAddress) == true, "Wrong signature for executor response!");
        
        //Mark the party as not-challenged in the challenge list
        contracts[id].challengedWatchdogs[index] = 0;
        
        //Notify clients
        emit WatchdogResponse(id, msg.data);
    }
    
    //Finalizes a watchdog challenge and kicks all watchdogs that have not responded
    function watchdogFinalization(uint id) public updateIncrementalTxHash(id, 0){
        
        //Checks
        require(contracts[id].phase == Phase.CHALLENGE_WATCHDOG, "Not the right phase to provude a watchdog response");
        require(contracts[id].deadline < now, "The response deadline has not expired!");
        
        //Drop the watchdogs, that have not responded (The executor is ignored here)
        for(uint i = 0; i < POOL_SIZE; i++){
            if(contracts[id].challengedWatchdogs[i] == 1){
                contracts[id].operators[i] = address(0);       //A kicked watchdog is simply one with address(0)
            }
        }
        
        //Return to the correct phase
        contracts[id].phase = contracts[id].fallbackPhase;
        contracts[id].watchdogsChallenged = contracts[id].watchdogsChallenged + 1;
        
        //Increase the timeout if there is an outer creation or executor challenge
        if (contracts[id].phase == Phase.CHALLENGE_EXECUTOR || contracts[id].phase == Phase.CREATION) {
            contracts[id].deadline = now + TIMEOUT_INTERVAL;
        }
        
        //Notify clients
        emit WatchdogFinalized(id, msg.data);
    }
    
    //******************
    //Modifiers
    
    //This code is executed after each public function (besides initCreation) to include the new transaction into the contract-tx-history-hash
    modifier updateIncrementalTxHash(uint id, uint value) {
        _;
        //@ClientDeveloper: Check here how the incremental hash is created
        contracts[id].incrementalTxHash = keccak256(abi.encode(contracts[id].incrementalTxHash, msg.data, msg.sender, value));
    }
    
    //******************
    //Private functions (Mainly prevent duplicate code)
    
    //Duplicate code used by both watchdog challenges which dupdates the state and emits the event
    function internalWatchdogChallenge(uint id, bytes memory message, uint8[POOL_SIZE] memory challengedOperators) private {
        
        //Update state
        contracts[id].fallbackPhase = contracts[id].phase;
        contracts[id].phase = Phase.CHALLENGE_WATCHDOG;
        contracts[id].deadline = now + TIMEOUT_INTERVAL;
        contracts[id].watchdogChallengeHash = keccak256(message);
        contracts[id].challengedWatchdogs = challengedOperators;
        
        //Notify clients
        emit WatchdogChallenged(id, msg.data);
    }
    
    //******************
    //Public helper functions
    
    //Verifies ECDSA signatures of Ethereum addresses
    //function verifySignature(bytes32 signedHash, bytes memory signature, address signer) public pure returns (bool) {
    //    
    //    //Parse the signature
    //    (uint8 v, bytes32 r, bytes32 s) = abi.decode(signature, (uint8, bytes32, bytes32));
    //    
    //    //Verify the signature
    //    return (ecrecover(signedHash, v, r, s) == signer);
    //}
    
    //Verifies ECDSA signatures of prefixed and hashed encoded data: Hash the data, prefix it, hash it again, verify it against signature
    //TODO: If our client does not prefix we can use the funciton above
    function verifySignature(bytes32 _hashedDataInput, bytes memory _signature, address _party) public pure returns (bool){

        //Convert signatures
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(_signature, (uint8, bytes32, bytes32));

        //Calc prefixed hash
        bytes32 _hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashedDataInput));

        return _party == ecrecover(_hash, v,r,s);

    }
}
