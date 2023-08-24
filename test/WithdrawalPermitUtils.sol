// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct WithdrawalPermit {
    address receiver;
    uint256 amount;
    uint256 deadline;
    uint256 nonce;
}

contract WithdrawalPermitUtils {
    bytes32 public constant WITHDRAWAL_PERMIT_TYPEHASH = keccak256(
        "WithdrawalPermit(address receiver,uint256 amount,uint256 deadline,uint256 nonce)"
    );

    // Computes hash of a withdrawal permit
    function getStructHash(
        WithdrawalPermit memory _permit,
        bytes32 _permitTypehash
    )
        internal
        pure
        returns (bytes32)
    {
        require(
            _permitTypehash == WITHDRAWAL_PERMIT_TYPEHASH,
            "Withdrawal permit type does not match."
        );
        return keccak256(
            abi.encode(
                WITHDRAWAL_PERMIT_TYPEHASH,
                _permit.receiver,
                _permit.amount,
                _permit.deadline,
                _permit.nonce
            )
        );
    }

    // Computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover a signer
    function getTypedDataHash(
        WithdrawalPermit memory _permit,
        bytes32 _domainSeparator,
        bytes32 _permitTypehash
    )
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", _domainSeparator, getStructHash(_permit, _permitTypehash)
            )
        );
    }
}
