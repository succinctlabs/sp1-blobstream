// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

// Required environment variables:
// - CONTRACT_ADDRESS
// - SP1_BLOBSTREAM_PROGRAM_VKEY
// - SP1_PROVER

contract UpgradeScript is BaseScript {
    using stdJson for string;

    function setUp() public {}

    string internal constant KEY = "UpgradeScript";

    /// Reads CONTRACT_ADDRESS_<CHAIN_ID> from the environment variables and updates the SP1 Verifier and program vkey.
    function run() external multichain(KEY) broadcaster {
        string memory contractAddressKey =
            string.concat("CONTRACT_ADDRESS_", vm.toString(block.chainid));
        address existingProxyAddress = vm.envAddress(contractAddressKey);

        SP1Vector sp1Vector = SP1Vector(address(existingProxyAddress));

        // // Update the SP1 Verifier address and the program vkey.
        // if (vm.envBool("MOCK")) {
        //     SP1MockVerifier mockVerifier = new SP1MockVerifier();
        //     sp1Vector.updateVerifier(address(mockVerifier));
        // } else {
        //     sp1Vector.updateVerifier(vm.envAddress("SP1_VERIFIER_ADDRESS"));
        // }

        sp1Vector.updateVectorXProgramVkey(vm.envBytes32("SP1_VECTOR_PROGRAM_VKEY"));
    }
}
