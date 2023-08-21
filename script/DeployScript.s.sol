// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.broadcast();
    }
}
