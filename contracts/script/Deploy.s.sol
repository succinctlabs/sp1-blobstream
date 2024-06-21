// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {SP1Blobstream} from "../src/SP1Blobstream.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {SP1Verifier} from "@sp1-contracts/SP1Verifier.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        SP1Blobstream lightClient;

        if (vm.envBool("DEPLOY")) {
            // Deploy Verifier
            // TODO: Detect SP1_PROVER=mock and use a mock verifier if specified.
            SP1Verifier verifier = new SP1Verifier();

            // Deploy contract
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
                    blobstreamXProgramVkey: vm.envBytes32("BLOBSTREAM_X_PROGRAM_VKEY"),
                    verifier: address(verifier)
                })
            );
        } else if (vm.envBool("UPGRADE")) {
            // Deploy contract
            SP1Blobstream lightClientImpl =
                new SP1Blobstream{salt: bytes32(vm.envBytes("CREATE2_SALT"))}();

            address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");

            lightClient = SP1Blobstream(existingProxyAddress);
            lightClient.upgradeTo(address(lightClientImpl));
        } else {
            lightClient = SP1Blobstream(vm.envAddress("CONTRACT_ADDRESS"));
        }

        if (vm.envBool("UPDATE_GENESIS_STATE")) {
            lightClient.updateGenesisState(
                uint32(vm.envUint("GENESIS_HEIGHT")), vm.envBytes32("GENESIS_HEADER")
            );
        }

        return address(lightClient);
    }
}
