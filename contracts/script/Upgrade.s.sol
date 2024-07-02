// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1Verifier} from "@sp1-contracts/SP1Verifier.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

// Required environment variables:
// - CONTRACT_ADDRESS
// - SP1_BLOBSTREAM_PROGRAM_VKEY
// - SP1_PROVER

contract UpgradeScript is Script {
    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        SP1Blobstream lightClient;

        // Deploy contract.
        SP1Blobstream lightClientImpl = new SP1Blobstream();
        address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");

        lightClient = SP1Blobstream(existingProxyAddress);
        lightClient.upgradeTo(address(lightClientImpl));

        // Update the SP1 Verifier address and the program vkey.
        if (vm.envBool("MOCK")) {
            SP1MockVerifier mockVerifier = new SP1MockVerifier();
            lightClient.updateVerifier(address(mockVerifier));
        } else {
            SP1Verifier verifier = new SP1Verifier();
            lightClient.updateVerifier(address(verifier));
        }
        lightClient.updateProgramVkey(vm.envBytes32("SP1_BLOBSTREAM_PROGRAM_VKEY"));

        return address(lightClient);
    }
}
