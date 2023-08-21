// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {Safe} from "safe-contracts/Safe.sol";

/// Error description.
error SomeError();

/**
 * @title TokenWithdrawalModule - Safe module, which allows accounts that are
 *                     not related to the Safe, to withdraw predetermined amount
 *                     of a specific token.
 */
contract TokenWithdrawalModule {
    struct WithdrawalPermit {
        address receiver;
        uint256 amount;
        uint256 deadline;
        uint256 nonce;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/
    event SomeEvent(uint256 indexed someIndex);

    /*//////////////////////////////////////////////////////////////
                            MODULE STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Safe contract, which this module is specific to.
    Safe public safe;

    /// @notice Token contract address, which this module is specific to.
    address public token;

    /// @notice Version of current implementation.
    string public constant VERSION = "1";

    /// @notice Typehash of EIP712 domain separator.
    /// @dev keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @notice Typehash of a WithdrawalPermit struct.
    /// @dev keccak256("WithdrawalPermit(address receiver,uint256 amount,uint256 deadline,uint256 nonce)")
    bytes32 public constant WITHDRAWAL_PERMIT_TYPEHASH =
        0x376ec1ee7725c08b84c4815757b4bc9078f548d4828e39acaed2a574e0738a13;

    /// @notice EIP-712 domain separator.
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice Mapping to keep track the nonce of all receivers.
    mapping(address => uint256) public nonces;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Constructor sets Safe and token addresses.
     * @param _safe Safe proxy address.
     * @param _token Token address.
     */
    constructor(address payable _safe, address _token) {
        safe = Safe(_safe);
        token = _token;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_SEPARATOR_TYPEHASH,
                keccak256(bytes(type(TokenWithdrawalModule).name)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                            WITHDRWAW LOGIC
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Method allows to withdraw `token` tokens from Safe 'safe'.
     * @dev Some dev info.
     * @param receiver Beneficiary address.
     * @param amount to withdraw.
     * @param signatures List of signatures.
     * @return True
     */
    function withdrawFromSafe(address receiver, uint256 amount, bytes memory signatures) external returns (bool) {
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          EIP-712 FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Encodes the withdrawal permit data into a EIP-712 message (ready to be hashed and sign).
     * @param receiver Beneficiary address.
     * @param amount Token amount to be transfered.
     * @param deadline Expiration timestamp.
     * @param nonce Beneficiary nonce.
     * @return EIP-712 message (66 bytes), ready to be hashed and signed.
     */
    function encodeWithdrawalPermitData(address receiver, uint256 amount, uint256 deadline, uint256 nonce)
        public
        view
        returns (bytes memory)
    {
        bytes32 withdrawalPermitHash =
            keccak256(abi.encode(WITHDRAWAL_PERMIT_TYPEHASH, receiver, amount, deadline, nonce));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), DOMAIN_SEPARATOR, withdrawalPermitHash);
    }

    /**
     * @notice Returns withdrawal permit hash, ready to be signed.
     * @param receiver Beneficiary address.
     * @param amount Token amount to be transfered.
     * @param deadline Expiration timestamp.
     * @param nonce Beneficiary nonce.
     * @return Withdrawal permit hash.
     */
    function getWithdrawalPermitHash(address receiver, uint256 amount, uint256 deadline, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(encodeWithdrawalPermitData(receiver, amount, deadline, nonce));
    }
}
