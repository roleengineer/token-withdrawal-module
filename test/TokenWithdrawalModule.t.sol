// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {TokenWithdrawalModule} from "src/TokenWithdrawalModule.sol";

contract TokenWithdrawalModuleTest is Test {
    TokenWithdrawalModule public tokenWithdrawalModule;

    function setUp() public {
        tokenWithdrawalModule = new TokenWithdrawalModule(payable(address(0x1)), address(0x2));
    }

    function test_Withdraw() public {}

    function testFuzz_Withdraw(uint256 x) public {}
}
