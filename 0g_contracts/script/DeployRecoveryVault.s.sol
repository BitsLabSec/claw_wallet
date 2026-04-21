// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";

import {RecoveryVault} from "../src/RecoveryVault.sol";

contract DeployRecoveryVault is Script {
    function run() external returns (RecoveryVault vault) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);
        vault = new RecoveryVault();
        vm.stopBroadcast();
    }
}

