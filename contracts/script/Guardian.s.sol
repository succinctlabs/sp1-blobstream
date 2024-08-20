// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

import {BaseScript} from "./Base.s.sol";

// Required environment variables:
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - CONTRACT_ADDRESS

contract UpdateGenesisStateScript is BaseScript {
    string internal constant KEY = "SP1_BLOBSTREAM";

    function run() external multichain(KEY) returns (address) {
        vm.startBroadcast();

        string memory contractAddressKey =
            string.concat("CONTRACT_ADDRESS_", vm.toString(block.chainid));
        // Upgrade the existing Blobstream.
        SP1Blobstream existingBlobstream = SP1Blobstream(vm.envAddress(contractAddressKey));

        existingBlobstream.grantRole(existingBlobstream.GUARDIAN_ROLE(), address(this));
        existingBlobstream.grantRole(existingBlobstream.TIMELOCK_ROLE(), address(this));
        existingBlobstream.grantRole(existingBlobstream.DEFAULT_ADMIN_ROLE(), address(this));


        existingBlobstream.renounceRole(existingBlobstream.GUARDIAN_ROLE(), address(this));
        existingBlobstream.renounceRole(existingBlobstream.TIMELOCK_ROLE(), address(this));
        existingBlobstream.renounceRole(existingBlobstream.DEFAULT_ADMIN_ROLE(), address(this));

        return address(lightClient);
    }
}
