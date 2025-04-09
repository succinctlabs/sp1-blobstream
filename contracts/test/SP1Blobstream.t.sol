// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/SP1Blobstream.sol";
import "forge-std/console2.sol"; // console no longer works (unknown selector)

contract SP1BlobstreamTest is Test {
    SP1Blobstream public blobstream;

    function setUp() public {
        // blobstream = new SP1Blobstream();
    }

    function testPacked() public pure {
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";

        bytes memory encodedInput = abi.encode(header, header);
        bytes memory packedEncodedInput = abi.encodePacked(header, header);
        require(keccak256(encodedInput) == keccak256(packedEncodedInput), "packed matches");
    }

    function testGetEncodePackedNextHeader() public view {
        // http://64.227.18.169:26657/block?height=10000
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        bytes memory encodedInput = abi.encodePacked(height, header);
        console.logBytes(encodedInput);
    }

    function testGetEncodePackedHeaderRange() public view {
        // http://64.227.18.169:26657/block?height=10000
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        uint64 requestedHeight = 10004;
        bytes memory encodedInput = abi.encodePacked(height, header, requestedHeight);
        console2.logBytes(encodedInput);
    }

    function testHoleskySP1Blobstream() public {
        vm.createSelectFork(vm.envString("RPC_HOLESKY"));
        blobstream = SP1Blobstream(0x315A044cb95e4d44bBf6253585FbEbcdB6fb41ef);

        // Owner
        vm.prank(0xBaB2c2aF5b91695e65955DA60d63aD1b2aE81126);

        uint64 latestBlock = blobstream.latestBlock();
        bytes32 latestHeader = blobstream.blockHeightToHeaderHash(latestBlock);
        console2.log(latestBlock);
        console2.logBytes32(latestHeader);

        // Relayer
        vm.prank(0x9c0B0dBBAe8a976CEeA8C2A96F6D00c53839afDC);

        bytes memory proof =
            hex"1b34fe1110286651778c86b74874f1420c9f6353af1778bea11e3b00f382afd80e7ed4db029af2a0b19dc994a8e7babc6aff8cb8d3c199751c7c8b7d78592affc3b119032d27fbcfa9e659e5c96859dc74abd03cbda24a5f1b80a03513a045b60541472c1e99af15f72cb88d6791302faad1ed7fbcf5b12c86909710cd0c6fce7be76a7506fc59a77a17ec8c06c7ba93d88703472724552c6e4533001f1e3944b6945bff0e0e8997da9508a3911d58cd64f7022dfb2cf2ed1c6272b7672f6275712357101d302543154c8a8112a65fe84848dc7819145ba75dab7ef682b5ed7482720c8526a35450bb5fe75a4074f70230271fd3ad2b1d9a0dded13272a5589005667df921ce3c267415b75cc937a6e01c2993f4ec81dba060df17aba147bee4127406eb28dac2b85697e97ac562d0976730225e22e5602a37b55d4630e0ba1b3ee76a8c1298e4624f7181a79adce2cdb93e56d22a7fdf45e9866d77cb233bf9a7fb0af803cf79090e2031e1adfdf82b09773b447b035b28aa1342519048239ca1c03f0008822f95b6c99333876c0dbafac8040f793a54f825790e29a0762994e5b8223913849c98b308a5d4cda71b91a3e3150a702559c93966a88236b96041297e66381f819ebfcd4bd181d092dda31bade8247d5b27e2a5dd0a942f378cb8a27c088f15b8f6dcb46a125aa02fc0155e8e35c6042dc2884b2811b1aa1f5bdb70e655c215e1cdcc563a6ccad399f33b7af26e108cd77a83ba4c81b60b237f35e44de8d3026455a0619391d7ab83ca7a09b578e9c876f79a223cee723a75c8fcfde8fec2228f6075d229732a04e72166484cc5fb812d7c462e3206bb3faf29b5a2122ab723417cf2f561c757380808aefcf0312848a10c379129e4bae7c6b7d1cb9eda320dfaf42aafec85314d86e6a513941f2553848365ca1aedde76ac01ca5b55bfce1bd9e7171183eaebb358d68b4088b15c33d329cd9833f0b2b767af239a5bc9f60d2b3f4803324c3ca0ff652b4296ef2d6c3f5d20a4f1df8cd5c8019b6cc543c92fac6112e5cce2431ebc13092029577529f1e77b990531f3831b9754175aa91205ff0b494ff5aa967896b2e2cf2b48753ff35e69be9e2fac75c7598c8b4917940b7f44a4469cd8b32b06ffe6aa5d8e2bff798a8e378b080a64fdfc72d0bc187725639d95d68105e2a83f3e3ee0bfe73469782198dc5dec1f17cb708a441e96ae";
        bytes memory publicValues =
            hex"2c805771c076399cb490823619ac6b7a5c9d95b6d566c18b5250fe2386ab4ef2a9c1d0d655cbb3b2907aa0af19432bd53142d1169c5002b8334f2c16ae6fc8621554ae15c3324c78ff9ed64fb2ac78d41d27b358952455b9d8b55389d878617d00000000000000000000000000000000000000000000000000000000004e183000000000000000000000000000000000000000000000000000000000004e3f40000000000000000000000000000000000000000fffffffffffffffffffffffff";

        blobstream.commitHeaderRange(proof, publicValues);

        // blobstream.initialize(17000);
    }
}
