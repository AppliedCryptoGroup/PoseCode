const PoseManager = artifacts.require("PoseManager_ECDSA");

module.exports = function (deployer) {
  deployer.deploy(PoseManager);
};
