// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "@openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

// Required environment variables:
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - CONTRACT_ADDRESS

contract UpdateGenesisStateScript is Script {
    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        SP1Blobstream lightClient = SP1Blobstream(vm.envAddress("CONTRACT_ADDRESS"));

        lightClient.updateGenesisState(
            uint32(vm.envUint("GENESIS_HEIGHT")), vm.envBytes32("GENESIS_HEADER")
        );

        return address(lightClient);
    }
}
