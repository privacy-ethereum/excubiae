// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BaseERC721Policy } from "./BaseERC721Policy.sol";
import { Factory } from "../../../proxy/Factory.sol";

/// @title BaseERC721PolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of BaseERC721Policy.
/// @dev Simplifies deployment of ERC721 policy clones with appended configuration data.
contract BaseERC721PolicyFactory is Factory {
    /// @notice Initializes the factory with the BaseERC721Policy implementation.
    constructor() Factory(address(new BaseERC721Policy())) { }

    /// @notice Deploys a new BaseERC721Policy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param _checkerAddr Address of the ERC721 checker to use for validation.
    function deploy(address _checkerAddr) public {
        // Encode the caller (owner) and checker address for appended data.
        bytes memory data = abi.encode(msg.sender, _checkerAddr);

        address clone = super._deploy(data);

        BaseERC721Policy(clone).initialize();
    }
}
