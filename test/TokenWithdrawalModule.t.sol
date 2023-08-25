// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {SafeTestUtils} from "test/SafeTestUtils.sol";
import "./WithdrawalPermitUtils.sol";
import {stdError} from "forge-std/StdError.sol";
import {console2} from "forge-std/Test.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {Safe} from "safe-contracts/Safe.sol";
import "src/TokenWithdrawalModule.sol";

contract Unicorn is ERC20 {
    constructor(address _safe, uint256 totalSupply) ERC20("Unicorn", "Unicorn", 18) {
        _mint(_safe, totalSupply);
    }
}

contract TokenWithdrawalModuleTest is SafeTestUtils {
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event TokenWithdrawalSuccess(
        address indexed beneficiary, uint256 indexed amount, uint256 indexed nonce
    );

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

    /*//////////////////////////////////////////////////////////////
                      WITHDRAW SUCCESS CASES
    //////////////////////////////////////////////////////////////*/

    /// @notice Beneficiary should withdraw amount of tokens from Safe.
    /// @dev Only EOA ECDSA secp256k1 signatures.
    function testFuzz_WithdrawTokensFromSafeEOASignatures(
        uint256 seed,
        address beneficiary,
        uint256 amount
    )
        public
    {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        vm.assume(beneficiary != address(0));
        // beneficiary has 0 tokens
        assertEq(unicorn.balanceOf(beneficiary), 0);
        // get ready safe
        (uint256[] memory privateKeys,) = _getReadySafe(seed);
        // prepare data
        uint256 expirationTimestamp = block.timestamp + 1;
        uint256 beneficiaryNonce = tokenWithdrawalModule.nonces(beneficiary);
        // get digest to sign
        bytes32 digest = tokenWithdrawalModule.getWithdrawalPermitHash(
            beneficiary, amount, expirationTimestamp, beneficiaryNonce
        );
        // safe owners sign data and compile signatures
        bytes memory signatures = _signDigestByEOAList(digest, privateKeys);

        // expect events to be emitted
        _expectSuccessEvents(beneficiary, amount, beneficiaryNonce);
        // call withrdaw token
        assertTrue(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
        // beneficiary nonce increased
        assertEq(tokenWithdrawalModule.nonces(beneficiary), beneficiaryNonce + 1);
        // beneficiary received amount
        assertEq(unicorn.balanceOf(beneficiary), amount);
    }

    /// @notice Beneficiary should withdraw amount of tokens from Safe.
    /// @dev Safe method approveHash used to validate permit.
    function testFuzz_WithdrawTokensFromSafeApproveHash(
        uint256 seed,
        address beneficiary,
        uint256 amount
    )
        public
    {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        vm.assume(beneficiary != address(0));

        // beneficiary has 0 tokens
        assertEq(unicorn.balanceOf(beneficiary), 0);
        // get ready safe
        (, address[] memory owners) = _getReadySafe(seed);
        // prepare data
        uint256 expirationTimestamp = block.timestamp + 1;
        uint256 beneficiaryNonce = tokenWithdrawalModule.nonces(beneficiary);
        // get digest to sign
        bytes32 digest = tokenWithdrawalModule.getWithdrawalPermitHash(
            beneficiary, amount, expirationTimestamp, beneficiaryNonce
        );
        // safe owners approve hash and compile signature
        bytes memory signatures = new bytes(owners.length * 65);
        for (uint256 i = 0; i < owners.length; i++) {
            // impersonate owner address to call approveHash on Safe
            address owner = owners[i];
            vm.startPrank(owner);
            vm.expectEmit(true, true, false, false, address(safe));
            emit ApproveHash(digest, owner);
            safe.approveHash(digest);
            assembly {
                let signaturePos := mul(0x41, i)
                mstore(add(signatures, add(signaturePos, 0x20)), owner)
                mstore8(add(signatures, add(signaturePos, 0x60)), 0x01)
            }
            vm.stopPrank();
        }

        // expect events to be emitted
        _expectSuccessEvents(beneficiary, amount, beneficiaryNonce);
        // call withrdaw token
        assertTrue(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
        // beneficiary nonce increased
        assertEq(tokenWithdrawalModule.nonces(beneficiary), beneficiaryNonce + 1);
        // beneficiary received amount
        assertEq(unicorn.balanceOf(beneficiary), amount);
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAW REVERT CASES
    //////////////////////////////////////////////////////////////*/

    /// @notice Should revert once signatures are expired after a set time.
    function testFuzz_RevertSignaturesExpired(
        uint256 seed,
        address beneficiary,
        uint256 amount
    )
        public
    {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        vm.assume(beneficiary != address(0));
        // get ready safe, get beneficiary nonce, pick deadline, get digest, sign.
        (uint256 expirationTimestamp, bytes memory signatures) =
            _prepareDataRevertCase(seed, beneficiary, amount);

        // make block.timestamp > expirationTimestamp
        vm.warp(expirationTimestamp + 3600);
        // expect tx revert
        vm.expectRevert(WithdrawalPermitExpired.selector);
        // call withrdaw token
        assertFalse(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
    }

    /// @notice Should revert on beneficiary address(0).
    function testFuzz_RevertBeneficiaryAddressZero(uint256 seed, uint256 amount) public {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        address beneficiary = address(0);
        // get ready safe, get beneficiary nonce, pick deadline, get digest, sign.
        (uint256 expirationTimestamp, bytes memory signatures) =
            _prepareDataRevertCase(seed, beneficiary, amount);

        // expect tx revert
        vm.expectRevert(BeneficiaryAddressZero.selector);
        // call withrdaw token
        assertFalse(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
    }

    /// @notice Should revert, when threshold requirement is not met.
    function testFuzz_RevertThresholdNotMet(
        uint256 seed,
        address beneficiary,
        uint256 amount
    )
        public
    {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        vm.assume(beneficiary != address(0));
        // get ready safe
        (uint256[] memory privateKeys, address[] memory owners) = _getReadySafe(seed);
        vm.assume(owners.length > 2);
        // prepare data
        uint256 expirationTimestamp = block.timestamp + 36_000;
        uint256 beneficiaryNonce = tokenWithdrawalModule.nonces(beneficiary);
        // get digest to sign
        bytes32 digest = tokenWithdrawalModule.getWithdrawalPermitHash(
            beneficiary, amount, expirationTimestamp, beneficiaryNonce
        );
        // reduce private keys array to become below threshold = array.length - 1
        uint256[] memory reducedPrivateKeys = new uint256[](privateKeys.length - 2);
        for (uint256 i = 0; i < reducedPrivateKeys.length; i++) {
            reducedPrivateKeys[i] = privateKeys[i];
        }

        // reduced number of safe owners sign data and compile signatures
        bytes memory signatures = _signDigestByEOAList(digest, reducedPrivateKeys);

        // expect tx revert
        vm.expectRevert("GS020");
        // call withrdaw token
        assertFalse(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
    }

    /// @notice Should revert, when address, which signed data, is not a Safe owner.
    function testFuzz_RevertSignerNotAOwner(
        uint256 seed,
        address beneficiary,
        uint256 amount
    )
        public
    {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        vm.assume(beneficiary != address(0));
        // get ready safe
        (uint256[] memory privateKeys, address[] memory owners) = _getReadySafe(seed);
        vm.assume(owners.length > 1);
        // prepare data
        uint256 expirationTimestamp = block.timestamp + 36_000;
        uint256 beneficiaryNonce = tokenWithdrawalModule.nonces(beneficiary);
        // get digest to sign
        bytes32 digest = tokenWithdrawalModule.getWithdrawalPermitHash(
            beneficiary, amount, expirationTimestamp, beneficiaryNonce
        );
        // insert private key, which does not belong to a Safe owner
        privateKeys[privateKeys.length - 1] = uint256(keccak256(abi.encode(beneficiary)));
        privateKeys[privateKeys.length - 2] =
            uint256(keccak256(abi.encode(beneficiary, amount)));

        // invalid owners sign data and compile signatures
        bytes memory signatures = _signDigestByEOAList(digest, privateKeys);

        // expect tx revert
        vm.expectRevert("GS026");
        // call withrdaw token
        assertFalse(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
    }

    /// @notice Should revert, when a Safe dissabled module.
    function testFuzz_RevertModuleDisabled(
        uint256 seed,
        address beneficiary,
        uint256 amount
    )
        public
    {
        // fuzzing assumptions
        vm.assume(amount < TOTAL_SUPPLY);
        vm.assume(beneficiary != address(0));
        // get ready safe, get beneficiary nonce, pick deadline, get digest, sign.
        (uint256 expirationTimestamp, bytes memory signatures) =
            _prepareDataRevertCase(seed, beneficiary, amount);

        // impersonate safe address to disable module
        vm.startPrank(address(safe));
        address SENTINEL_MODULES = address(0x1);
        vm.expectEmit(true, false, false, false, address(safe));
        emit DisabledModule(address(tokenWithdrawalModule));
        safe.disableModule(SENTINEL_MODULES, address(tokenWithdrawalModule));
        vm.stopPrank();

        // expect tx revert
        vm.expectRevert("GS104");
        // call withrdaw token
        assertFalse(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
    }

    /// @notice Should revert, when token amount requested more than Safe balance.
    function testFuzz_RevertInsufficientSafeBalance(
        uint256 seed,
        address beneficiary
    )
        public
    {
        // fuzzing assumptions
        vm.assume(beneficiary != address(0));
        // amount requested more than Safe balance
        uint256 amount = unicorn.balanceOf(address(safe)) + 1;
        // get ready safe, get beneficiary nonce, pick deadline, get digest, sign.
        (uint256 expirationTimestamp, bytes memory signatures) =
            _prepareDataRevertCase(seed, beneficiary, amount);

        // expect tx revert (solmate ERC20 handles this error case as arifmethic overflow)
        vm.expectRevert(stdError.arithmeticError);
        // call withrdaw token
        assertFalse(
            tokenWithdrawalModule.withdrawTokenFromSafe(
                beneficiary, amount, expirationTimestamp, signatures
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                        EIP-712 FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /// @notice Should calculate EIP-712 message and hash correctly.
    function testFuzz_EIP712Methods(
        address beneficiary,
        uint256 amount,
        uint256 deadline,
        uint256 nonce
    )
        public
    {
        // calculate domain separator
        bytes32 domainSeparator = keccak256(
            abi.encode(
                tokenWithdrawalModule.DOMAIN_SEPARATOR_TYPEHASH(),
                keccak256(bytes(tokenWithdrawalModule.NAME())),
                keccak256(bytes(tokenWithdrawalModule.VERSION())),
                block.chainid,
                address(tokenWithdrawalModule)
            )
        );
        assertEq(domainSeparator, tokenWithdrawalModule.DOMAIN_SEPARATOR());
        // get module withdrawal permit typehash
        bytes32 modulePermitTypeHash = tokenWithdrawalModule.WITHDRAWAL_PERMIT_TYPEHASH();

        // deploy WithdrawalPermitUtils
        WithdrawalPermitUtils withdrawalPermitUtils = new WithdrawalPermitUtils();
        // compile permit
        WithdrawalPermit memory permit = WithdrawalPermit({
            receiver: beneficiary,
            amount: amount,
            deadline: deadline,
            nonce: nonce
        });
        // calculate using module methods
        bytes memory message = tokenWithdrawalModule.encodeWithdrawalPermitData(
            beneficiary, amount, deadline, nonce
        );
        bytes32 messageHash = keccak256(message);
        assertEq(
            messageHash,
            tokenWithdrawalModule.getWithdrawalPermitHash(beneficiary, amount, deadline, nonce)
        );

        // prove results with withdrawal permit utils
        assertEq(
            messageHash,
            withdrawalPermitUtils.getTypedDataHash(
                permit, domainSeparator, modulePermitTypeHash
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    function _getReadySafe(uint256 seed)
        internal
        returns (uint256[] memory privateKeys, address[] memory owners)
    {
        // used SafeTestUtils
        (privateKeys, owners) = _generateSafeOwners(seed);
        assertTrue(_setupSafeAndEnableModule(safe, owners, address(tokenWithdrawalModule)));
    }

    function _expectSuccessEvents(
        address beneficiary,
        uint256 amount,
        uint256 beneficiaryNonce
    )
        internal
    {
        vm.expectEmit(true, true, true, false, address(unicorn));
        emit Transfer(address(safe), beneficiary, amount);
        vm.expectEmit(true, false, false, false, address(safe));
        emit ExecutionFromModuleSuccess(address(tokenWithdrawalModule));
        vm.expectEmit(true, true, false, false, address(tokenWithdrawalModule));
        emit TokenWithdrawalSuccess(beneficiary, amount, beneficiaryNonce);
    }

    function _prepareDataRevertCase(
        uint256 seed,
        address beneficiary,
        uint256 amount
    )
        internal
        returns (uint256 expirationTimestamp, bytes memory signatures)
    {
        // get ready safe
        (uint256[] memory privateKeys,) = _getReadySafe(seed);
        // prepare data
        expirationTimestamp = block.timestamp + 36_000;
        uint256 beneficiaryNonce = tokenWithdrawalModule.nonces(beneficiary);
        // get digest to sign
        bytes32 digest = tokenWithdrawalModule.getWithdrawalPermitHash(
            beneficiary, amount, expirationTimestamp, beneficiaryNonce
        );
        // safe owners sign data and compile signatures
        signatures = _signDigestByEOAList(digest, privateKeys);
    }
}
