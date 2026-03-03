// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AdvancedERC721Policy } from "./AdvancedERC721Policy.sol";
import { Factory } from "../../../proxy/Factory.sol";

/// @title AdvancedERC721PolicyFactory
/// @notice Factory for deploying minimal proxy instances of AdvancedERC721Policy.
/// @dev Encodes configuration data for multi-phase policy validation.
contract AdvancedERC721PolicyFactory is Factory {
    /// @notice Initializes the factory with the AdvancedERC721Policy implementation.
    constructor() Factory(address(new AdvancedERC721Policy())) { }

    /// @notice Deploys a new AdvancedERC721Policy clone.
    /// @param _checkerAddr Address of the associated checker contract.
    /// @param _skipPre Whether to skip pre-checks.
    /// @param _skipPost Whether to skip post-checks.
    function deploy(address _checkerAddr, bool _skipPre, bool _skipPost) public {
        bytes memory data = abi.encode(msg.sender, _checkerAddr, _skipPre, _skipPost);

        address clone = super._deploy(data);

        AdvancedERC721Policy(clone).initialize();
    }
}
