// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

import {BaseScript} from "./Base.s.sol";

// Required environment variables:
// - SP1_PROVER
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - SP1_BLOBSTREAM_PROGRAM_VKEY
// - CREATE2_SALT
// - SP1_VERIFIER_ADDRESS

contract DeployScript is BaseScript {
    function setUp() public {}

    string internal constant KEY = "SP1_BLOBSTREAM";

    function run() external multichain(KEY) returns (address) {
        vm.startBroadcast();

        SP1Blobstream lightClient;
        ISP1Verifier verifier = ISP1Verifier(
            vm.envOr("SP1_VERIFIER_ADDRESS", 0x3B6041173B80E77f038f3F2C0f9744f04837185e)
        );

        // Deploy the SP1Blobstream contract.
        SP1Blobstream lightClientImpl =
            new SP1Blobstream{salt: bytes32(vm.envBytes("CREATE2_SALT"))}();
        lightClient = SP1Blobstream(
            address(
                new ERC1967Proxy{salt: bytes32(vm.envBytes("CREATE2_SALT"))}(
                    address(lightClientImpl), ""
                )
            )
        );

        // Initialize the Blobstream X light client.
        lightClient.initialize(
            SP1Blobstream.InitParameters({
                guardian: msg.sender,
                height: uint32(vm.envUint("GENESIS_HEIGHT")),
                header: vm.envBytes32("GENESIS_HEADER"),
                blobstreamProgramVkey: vm.envBytes32("SP1_BLOBSTREAM_PROGRAM_VKEY"),
                verifier: address(verifier)
            })
        );

        return address(lightClient);
    }
}
