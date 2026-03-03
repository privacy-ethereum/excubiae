// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { LibClone } from "solady/src/utils/LibClone.sol";
import { IFactory } from "../interfaces/IFactory.sol";

/// @title Factory
/// @notice Abstract base contract for deploying clone contracts.
/// @dev Provides functionality to deploy minimal proxy contracts using a standard implementation address.
abstract contract Factory is IFactory {
    /// @notice Address of the implementation contract used for cloning.
    /// @dev This address is immutable and defines the logic contract for all clones deployed by the factory.
    address public immutable IMPLEMENTATION;

    /// @notice Initializes the factory with the implementation contract address.
    /// @param _implementation Address of the logic contract to use for clones.
    constructor(address _implementation) {
        IMPLEMENTATION = _implementation;
    }

    /// @notice Deploys a new clone contract.
    /// @dev Uses `LibClone` to deploy a minimal proxy contract with appended initialization data.
    /// Emits a `CloneDeployed` event upon successful deployment.
    /// @param data Initialization data to append to the clone.
    /// @return clone Address of the deployed clone contract.
    function _deploy(bytes memory data) internal returns (address clone) {
        clone = LibClone.clone(IMPLEMENTATION, data);

        emit CloneDeployed(clone);
    }
}
