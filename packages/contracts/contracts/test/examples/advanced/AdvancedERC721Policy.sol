// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AdvancedPolicy } from "../../../policy/AdvancedPolicy.sol";

/// @title AdvancedERC721Policy
/// @notice Three-phase policy contract for ERC721 validation.
/// @dev Leverages AdvancedChecker for pre, main, and post validation phases.
contract AdvancedERC721Policy is AdvancedPolicy {
    /// @notice Returns a unique identifier for the policy.
    /// @return The string identifier "AdvancedERC721".
    function trait() external pure returns (string memory) {
        return "AdvancedERC721";
    }
}
