// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {TokenWithdrawalModule} from "src/TokenWithdrawalModule.sol";
import {Safe} from "safe-contracts/Safe.sol";

contract DeployScript is Script {
    function setUp() public {}

    function deployModule(address payable _safe, address _token) public {
        vm.startBroadcast();
        TokenWithdrawalModule module = new TokenWithdrawalModule(Safe(_safe), _token);
        console2.log(address(module));
        vm.stopBroadcast();
    }
}
