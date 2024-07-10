// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1MockVerifier} from "sp1-contracts/src/SP1MockVerifier.sol";
import {ISP1Verifier} from "sp1-contracts/src/ISP1Verifier.sol";

// Required environment variables:
// - SP1_PROVER
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - SP1_BLOBSTREAM_PROGRAM_VKEY
// - CREATE2_SALT
// - SP1_VERIFIER_ADDRESS

contract DeployScript is Script {
    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        ERC1967Proxy proxy = new ERC1967Proxy(0x43F8943CE01a8d47d3D4153df76806b41e139499, "");

        vm.stopBroadcast();

        return address(proxy);
    }
}
