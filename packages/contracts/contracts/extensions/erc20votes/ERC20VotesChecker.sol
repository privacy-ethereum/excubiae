// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IVotes } from "@openzeppelin/contracts/governance/utils/IVotes.sol";

import { BaseChecker } from "../../checker/BaseChecker.sol";

/// @title ERC20VotesChecker
/// @notice ERC20Votes validator.
/// @dev Extends BaseChecker to implement ERC20Votes validation logic.
contract ERC20VotesChecker is BaseChecker {
    /// @notice the token to check
    IVotes public token;

    /// @notice the snapshot block
    uint256 public snapshotBlock;

    /// @notice the threshold
    uint256 public threshold;

    /// @notice the balance is too low
    error BalanceTooLow();

    /// @notice Initializes the contract.
    function _initialize() internal override {
        super._initialize();

        bytes memory data = _getAppendedBytes();
        (address _token, uint256 _snapshotBlock, uint256 _threshold) = abi.decode(data, (address, uint256, uint256));

        token = IVotes(_token);
        snapshotBlock = _snapshotBlock;
        threshold = _threshold;
    }

    /// @notice Returns true for everycall.
    /// @param subject Address to validate.
    /// @param evidence Encoded data used for validation.
    /// @return Boolean indicating whether the subject passes the check.
    function _check(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._check(subject, evidence);

        // get the token balance at the snapshot block
        uint256 balance = token.getPastVotes(subject, snapshotBlock);

        // check if the balance is enough
        if (balance <= threshold) {
            revert BalanceTooLow();
        }

        return true;
    }
}
