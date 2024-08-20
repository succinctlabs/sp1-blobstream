// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

import {BaseScript} from "./Base.s.sol";

contract UpdateGenesisStateScript is BaseScript {
    string internal constant KEY = "SP1_BLOBSTREAM";

    function run() external multichain(KEY) broadcaster {
        string memory contractAddressKey =
            string.concat("CONTRACT_ADDRESS_", vm.toString(block.chainid));
        SP1Blobstream existingBlobstream = SP1Blobstream(vm.envAddress(contractAddressKey));

        // New multi-sig guardian.
        address newGuardian = address(0xBaB2c2aF5b91695e65955DA60d63aD1b2aE81126);

        existingBlobstream.grantRole(existingBlobstream.GUARDIAN_ROLE(), newGuardian);
        existingBlobstream.grantRole(existingBlobstream.TIMELOCK_ROLE(), newGuardian);
        existingBlobstream.grantRole(existingBlobstream.DEFAULT_ADMIN_ROLE(), newGuardian);

        existingBlobstream.renounceRole(existingBlobstream.GUARDIAN_ROLE(), msg.sender);
        existingBlobstream.renounceRole(existingBlobstream.TIMELOCK_ROLE(), msg.sender);
        existingBlobstream.renounceRole(existingBlobstream.DEFAULT_ADMIN_ROLE(), msg.sender);
    }
}
