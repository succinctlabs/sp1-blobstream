// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {stdJson} from "forge-std/StdJson.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {BaseScript} from "./Base.s.sol";

// Required environment variables:
// - CHAINS (comma separated list of chain names)
// - CONTRACT_ADDRESS_{CHAIN_ID}

contract UpdateVkeyScript is BaseScript {
    using stdJson for string;

    function setUp() public {}

    string internal constant KEY = "UpdateVkey";

    /// Reads CONTRACT_ADDRESS_<CHAIN_ID> from the environment variables and updates the SP1 Verifier and program vkey.
    function run() external multichain(KEY) broadcaster {
        string memory contractAddressKey = string.concat("CONTRACT_ADDRESS_", vm.toString(block.chainid));
        address existingProxyAddress = vm.envAddress(contractAddressKey);

        SP1Blobstream sp1Blobstream = SP1Blobstream(address(existingProxyAddress));

        // v4 program vkey
        sp1Blobstream.updateProgramVkey(0x00b6c8c78a73630fae80e45b2888a00d9ab0cc05a77cd7c027446a6ae2289928);
    }
}
