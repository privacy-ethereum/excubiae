// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { EASChecker } from "./EASChecker.sol";

/// @title EASCheckerFactory
/// @notice Factory contract for deploying minimal proxy instances of EASChecker.
/// @dev Simplifies deployment of EASChecker clones with appended configuration data.
contract EASCheckerFactory is Factory {
    /// @notice Initializes the factory with the EASChecker implementation.
    constructor() Factory(address(new EASChecker())) { }

    /// @notice Deploys a new EASChecker clone.
    /// @param eas The EAS contract
    /// @param attester The trusted attester
    /// @param schema The schema UID
    /// @return clone The address of the newly deployed EASChecker clone.
    function deploy(address eas, address attester, bytes32 schema) public returns (address clone) {
        bytes memory data = abi.encode(eas, attester, schema);

        clone = super._deploy(data);

        EASChecker(clone).initialize();
    }
}
