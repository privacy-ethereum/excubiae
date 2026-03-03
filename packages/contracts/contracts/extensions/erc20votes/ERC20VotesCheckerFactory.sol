// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { ERC20VotesChecker } from "./ERC20VotesChecker.sol";

/// @title ERC20VotesCheckerFactory
/// @notice Factory contract for deploying minimal proxy instances of ERC20VotesChecker.
/// @dev Simplifies deployment of ERC20VotesChecker clones with appended configuration data.
contract ERC20VotesCheckerFactory is Factory {
    /// @notice Initializes the factory with the ERC20VotesChecker implementation.
    constructor() Factory(address(new ERC20VotesChecker())) { }

    /// @notice Deploys a new ERC20VotesChecker clone.
    /// @return clone The address of the newly deployed ERC20VotesChecker clone.
    function deploy(address _token, uint256 _snapshotBlock, uint256 _threshold) public returns (address clone) {
        bytes memory data = abi.encode(_token, _snapshotBlock, _threshold);

        clone = super._deploy(data);

        ERC20VotesChecker(clone).initialize();
    }
}
