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
        sp1Blobstream.updateProgramVkey(0x00a4a07806c0cb9bc8fcc14fed368a161b947d13b4a4fd58eb382d07a3373ef7);
    }
}
