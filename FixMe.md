# Fix Me

One of our smart contracts, ./SmartContract/contracts/PoseManager_RSA, needs to be fixed before being executed and compiled. The fix can be made as follows:
- Copy the contents from [this contract](https://github.com/adria0/SolRsaVerify/blob/5746d395d782ebb7f1bf599c510c4942c9f18e25/contracts/SolRsaVerify.sol) to ./SmartContract/contracts/RSALibrary.sol
- Replace `library SolRsaVerify {` (Line 25) in file ./SmartContract/contracts/RSALibrary.sol with `contract SolRsaVerify {`
