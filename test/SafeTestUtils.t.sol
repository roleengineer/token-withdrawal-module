// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {SafeTestUtils} from "test/SafeTestUtils.sol";
import {Safe} from "safe-contracts/Safe.sol";

contract MockModule {
    address public safe;

    constructor(address _safe) {
        safe = _safe;
    }
}

contract SafeTestUtilsTest is SafeTestUtils {
    address mockModule;

    function setUp() public {
        mockModule = address(new MockModule(address(0xbeaf)));
    }

    /// @notice Should setup safe and enable module. Module can be disabled and enabled.
    function testFuzz_SetupEnableModule(uint256 seed) public {
        Safe safe = _getSafeTemplate();
        (, address[] memory owners) = _generateSafeOwners(seed);
        // module is not enabled.
        assertFalse(safe.isModuleEnabled(mockModule));
        // call setup and enable module.
        assertTrue(_setupSafeAndEnableModule(safe, owners, mockModule));
        // module is enabled.
        assertTrue(safe.isModuleEnabled(mockModule));
        // impersonate safe address and prove that module can be disabled and enabled again.
        vm.startPrank(address(safe));
        // disable module
        vm.expectEmit(true, false, false, false, address(safe));
        emit DisabledModule(mockModule);
        safe.disableModule(address(0x1), mockModule);
        assertFalse(safe.isModuleEnabled(mockModule));
        // enable module
        vm.expectEmit(true, false, false, false, address(safe));
        emit EnabledModule(mockModule);
        safe.enableModule(mockModule);
        assertTrue(safe.isModuleEnabled(mockModule));
        vm.stopPrank();
    }
}
