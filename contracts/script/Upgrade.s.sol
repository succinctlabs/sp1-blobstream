// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1MockVerifier} from "sp1-contracts/src/SP1MockVerifier.sol";
import {ISP1Verifier} from "sp1-contracts/src/ISP1Verifier.sol";

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
        ISP1Verifier verifier = ISP1Verifier(address(vm.envAddress("SP1_VERIFIER_ADDRESS")));
        lightClient.updateVerifier(address(verifier));
        lightClient.updateProgramVkey(vm.envBytes32("SP1_BLOBSTREAM_PROGRAM_VKEY"));

        return address(lightClient);
    }
}
