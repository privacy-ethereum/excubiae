// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IPolicy } from "../interfaces/IPolicy.sol";
import { Clone } from "../proxy/Clone.sol";

/// @title Policy
/// @notice Abstract base contract for implementing policies to enforce access control.
/// @dev Extends Clone and Ownable to provide policy initialization, ownership, and guarded management.
abstract contract Policy is Clone, IPolicy, Ownable(msg.sender) {
    /// @notice The address of the contract being protected by the policy.
    /// @dev Can only be set once by the owner.
    address public guarded;

    /// @notice Modifier to restrict access to only the guarded contract.
    modifier onlyTarget() {
        if (msg.sender != guarded) revert TargetOnly();
        _;
    }

    /// @notice Initializes the contract and sets the owner.
    /// @dev Overrides Clone's `_initialize` to include owner setup.
    function _initialize() internal virtual override {
        super._initialize();

        // Sets the factory as the initial owner.
        _transferOwnership(msg.sender);
    }

    /// @notice Sets the contract address to be protected by this policy.
    /// @dev Can only be called once by the owner.
    /// @param _guarded The contract address to protect.
    function setTarget(address _guarded) external virtual onlyOwner {
        if (_guarded == address(0)) revert ZeroAddress();
        if (guarded != address(0)) revert TargetAlreadySet();

        guarded = _guarded;
        emit TargetSet(_guarded);
    }
}
