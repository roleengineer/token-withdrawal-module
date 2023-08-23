// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {SafeTestUtils} from "test/SafeTestUtils.sol";
import {console2} from "forge-std/Test.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {TokenWithdrawalModule} from "src/TokenWithdrawalModule.sol";
import {Safe} from "safe-contracts/Safe.sol";

contract Unicorn is ERC20 {
    constructor(address _safe, uint256 totalSupply) ERC20("Unicorn", "Unicorn", 18) {
        _mint(_safe, totalSupply);
    }
}

contract TokenWithdrawalModuleTest is SafeTestUtils {
    uint256 constant TOTAL_SUPPLY = 100_000_000 ether;
    Safe safe;
    Unicorn unicorn;
    TokenWithdrawalModule public tokenWithdrawalModule;

    function setUp() public {
        // deploys safe proxy without setup
        safe = _getSafeTemplate();
        // deploys ERC20 token and mints totalSupply to safe
        unicorn = new Unicorn(address(safe), TOTAL_SUPPLY);
        // deploys tested module with specific Safe and token
        tokenWithdrawalModule = new TokenWithdrawalModule(safe, address(unicorn));
    }

    function testFuzz_WithdrawTokensFromSafe(uint256 seed, address beneficiary, uint256 amount) public {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        vm.assume(beneficiary != address(0));
        // beneficiary has 0 tokens
        assertEq(unicorn.balanceOf(beneficiary), 0);
        // get ready safe
        (uint256[] memory privateKeys, address[] memory owners) = _generateSafeOwners(seed);
        assertTrue(_setupSafeAndEnableModule(safe, owners, address(tokenWithdrawalModule)));
        // prepare data
        uint256 expirationTimestamp = block.timestamp + 1;
        uint256 beneficiaryNonce = tokenWithdrawalModule.nonces(beneficiary);
        // get digest to sign
        bytes32 digest =
            tokenWithdrawalModule.getWithdrawalPermitHash(beneficiary, amount, expirationTimestamp, beneficiaryNonce);
        // sign data and compile signatures
        bytes memory signatures = _signDigestByEOAList(digest, privateKeys);

        vm.expectEmit(true, false, false, false, address(safe));
        emit ExecutionFromModuleSuccess(address(tokenWithdrawalModule));
        // call withrdaw token
        assertTrue(tokenWithdrawalModule.withdrawTokenFromSafe(beneficiary, amount, expirationTimestamp, signatures));
        // beneficiary received amount
        assertEq(unicorn.balanceOf(beneficiary), amount);
    }
}
