const Migrations = artifacts.require("Migrations");
const PoseManager = artifacts.require("PoseManager_ECDSA");

module.exports = function (deployer) {
  deployer.deploy(Migrations);
  deployer.deploy(PoseManager);
};
