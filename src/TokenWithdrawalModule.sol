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
    struct SomeStruct {
        uint256 amount;
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
    function withdrawFromSafe(address receiver, uint256 amount, bytes memory signatures)
        external
        returns (bool)
    {
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice View method returns something.
     * @param someparam description.
     * @return somereturndata description.
     */
    function getSomething(bytes32 someparam)
        external
        view
        returns (bytes memory somereturndata)
    {
        somereturndata = "";
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _getSomething(uint256 index)
        internal
        returns (uint256 something)
    {
        something = 0;
    }

}
