// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BasePolicy } from "../../../policy/BasePolicy.sol";

/// @title BaseERC721Policy
/// @notice Policy contract enforcing NFT-based validation.
/// @dev Extends BasePolicy to add specific behavior for ERC721 token validation.
contract BaseERC721Policy is BasePolicy {
    /// @notice Returns a trait identifier for the policy.
    /// @dev Used to identify the policy type.
    /// @return The trait string "BaseERC721".
    function trait() external pure returns (string memory) {
        return "BaseERC721";
    }
}
