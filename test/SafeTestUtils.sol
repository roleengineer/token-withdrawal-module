// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Safe} from "safe-contracts/Safe.sol";
import {SafeProxyFactory} from "safe-contracts/proxies/SafeProxyFactory.sol";

/// @title Safe specific extension of a forge test contract.
contract SafeTestUtils is Test {
    event EnabledModule(address indexed module);
    event DisabledModule(address indexed module);
    event ExecutionFromModuleSuccess(address indexed module);
    event ExecutionFromModuleFailure(address indexed module);
    event ApproveHash(bytes32 indexed approvedHash, address indexed owner);

    Safe singleton = new Safe();
    SafeProxyFactory factory = new SafeProxyFactory();

    /*//////////////////////////////////////////////////////////////
                        SAFE SPECIFIC UTILS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns deployed safe proxy without setup.
    function _getSafeTemplate() internal returns (Safe safeTemplate) {
        safeTemplate =
            Safe(payable(address(factory.createProxyWithNonce(address(singleton), "", 0))));
    }

    /// @notice Generates sorted list of owners addresses and corresponding private keys.
    /// @dev Used for different Safe setups based on fuzzing input.
    function _generateSafeOwners(uint256 seed)
        internal
        pure
        returns (uint256[] memory privateKeys, address[] memory owners)
    {
        uint256 ownerCount = seed % 5;
        if (ownerCount == 0) ownerCount = 1;

        privateKeys = new uint256[](ownerCount);
        owners = new address[](ownerCount);

        for (uint256 i = 0; i < ownerCount; i++) {
            uint256 privateKey = uint256(keccak256(abi.encodePacked(seed, i)));
            while (
                privateKey > 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
            ) {
                privateKey = uint256(keccak256(abi.encodePacked(privateKey)));
            }
            address owner = vm.addr(privateKey);
            uint256 index = i;
            while (index > 0 && owners[index - 1] > owner) {
                owners[index] = owners[index - 1];
                privateKeys[index] = privateKeys[index - 1];
                index--;
            }
            owners[index] = owner;
            privateKeys[index] = privateKey;
        }
    }

    /// @notice Calls Safe setup function and enables provided module.
    function _setupSafeAndEnableModule(
        Safe _safe,
        address[] memory owners,
        address moduleToEnable
    )
        internal
        returns (bool moduleEnabled)
    {
        uint256 threshold = owners.length > 1 ? owners.length - 1 : owners.length;
        // prepare calldata for delegatecall from Safe to this contract
        bytes memory enableModuleData =
            abi.encodeWithSignature("enableSafeModule(address)", moduleToEnable);
        // call Safe setup
        _safe.setup(
            owners,
            threshold,
            address(this),
            enableModuleData,
            address(0),
            address(0),
            0,
            payable(address(0))
        );
        // return true, if module was enabled successfully
        moduleEnabled = _safe.isModuleEnabled(moduleToEnable);
    }

    /// @notice Signs digest by the list of private keys and returns concatenated signatures.
    function _signDigestByEOAList(
        bytes32 digest,
        uint256[] memory privateKeys
    )
        internal
        pure
        returns (bytes memory signatures)
    {
        signatures = new bytes(privateKeys.length * 65);
        for (uint256 i = 0; i < privateKeys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[i], digest);
            assembly {
                let signaturePos := mul(0x41, i)
                mstore(add(signatures, add(signaturePos, 0x20)), r)
                mstore(add(signatures, add(signaturePos, 0x40)), s)
                mstore8(add(signatures, add(signaturePos, 0x60)), v)
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              CALLBACK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Callback function, which enables the module `module` for the Safe.
     * @dev This is done via a setup function call.
     * @param module Module to be whitelisted.
     */
    function enableSafeModule(address module) external {
        uint256 modulesSlot = uint256(1);
        uint256 modulePadded = uint256(uint160(module));
        bytes32 moduleSlot = keccak256(abi.encodePacked(modulePadded, modulesSlot));
        // uint256(SENTINEL_MODULES) == modulesSlot
        bytes32 sentinelModulesSlot = keccak256(abi.encodePacked(modulesSlot, modulesSlot));
        assembly {
            // load module, which SENTINEL_MODULES points to
            let nextModule := sload(sentinelModulesSlot)
            // module points to loaded module
            sstore(moduleSlot, nextModule)
            // SENTINEL_MODULES points to module
            sstore(sentinelModulesSlot, modulePadded)
        }
    }
}
