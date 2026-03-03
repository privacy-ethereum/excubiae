// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { GitcoinPassportChecker } from "./GitcoinPassportChecker.sol";

/// @title GitcoinPassportCheckerFactory
/// @notice Factory contract for deploying minimal proxy instances of GitcoinPassportChecker.
/// @dev Simplifies deployment of GitcoinPassportChecker clones with appended configuration data.
contract GitcoinPassportCheckerFactory is Factory {
    /// @notice Initializes the factory with the GitcoinPassportChecker implementation.
    constructor() Factory(address(new GitcoinPassportChecker())) { }

    /// @notice Deploys a new GitcoinPassportChecker clone.
    /// @param passportDecoder The GitcoinPassportDecoder contract
    /// @param thresholdScore The threshold score to be considered human
    /// @return clone The address of the newly deployed GitcoinPassportChecker clone.
    function deploy(address passportDecoder, uint256 thresholdScore) public returns (address clone) {
        bytes memory data = abi.encode(passportDecoder, thresholdScore);

        clone = super._deploy(data);

        GitcoinPassportChecker(clone).initialize();
    }
}
