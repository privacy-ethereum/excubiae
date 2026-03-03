// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { ERC20Checker } from "./ERC20Checker.sol";

/// @title ERC20CheckerFactory
/// @notice Factory contract for deploying minimal proxy instances of ERC20Checker.
/// @dev Simplifies deployment of ERC20Checker clones with appended configuration data.
contract ERC20CheckerFactory is Factory {
    /// @notice Initializes the factory with the ERC20Checker implementation.
    constructor() Factory(address(new ERC20Checker())) { }

    /// @notice Deploys a new ERC20VotesChecker clone.
    /// @return clone The address of the newly deployed ERC20VotesChecker clone.
    function deploy(address _token, uint256 _threshold) public returns (address clone) {
        bytes memory data = abi.encode(_token, _threshold);

        clone = super._deploy(data);

        ERC20Checker(clone).initialize();
    }
}
