// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { TokenChecker } from "./TokenChecker.sol";

/// @title TokenCheckerFactory
/// @notice Factory contract for deploying minimal proxy instances of TokenChecker.
/// @dev Utilizes the Factory pattern to streamline deployment of TokenChecker clones with configuration data.
contract TokenCheckerFactory is Factory {
    /// @notice Initializes the factory with the TokenChecker implementation.
    /// @dev The constructor sets the TokenChecker contract as the implementation for cloning.
    constructor() Factory(address(new TokenChecker())) { }

    /// @notice Deploys a new TokenChecker clone with the specified ERC721 token contract.
    /// @dev Encodes the ERC721 token contract address as initialization data for the clone.
    /// @param token Address of the ERC721 token contract.
    /// @return clone The address of the newly deployed TokenChecker clone.
    function deploy(address token) public returns (address clone) {
        bytes memory data = abi.encode(token);
        clone = super._deploy(data);

        TokenChecker(clone).initialize();
    }
}
