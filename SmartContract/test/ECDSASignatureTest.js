const PoseManager = artifacts.require("PoseManager_ECDSA");

contract("Manager contract", async accounts => {
  it("register", async () => {

    let instance = await PoseManager.deployed();

    //Hard-coded signer:
    let signer = web3.eth.accounts.privateKeyToAccount("0xb0057716d5917badaf911b193b12b910811c1497b5bada8d7711f758981c3773");

    //Attestation hash:
    let attestHash = web3.utils.keccak256(web3.eth.abi.encodeParameters(['string', 'bytes32', 'address', 'bytes'], ['Pose-Attest', "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563", "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1","0x00"]));

    //EncodedAttestationSignature
    let signature = signer.sign(attestHash);
    let encodedSignature = web3.eth.abi.encodeParameters(["uint8","bytes32","bytes32"],[signature.v,signature.r,signature.s])

    await instance.register("0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1", "0x00", encodedSignature);

    assert.equal(0,0);
  });
});
