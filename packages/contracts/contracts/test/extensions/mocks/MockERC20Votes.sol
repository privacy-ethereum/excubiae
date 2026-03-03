// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockERC20Votes
/// @notice A mock ERC20Votes contract
contract MockERC20Votes is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {
        _mint(msg.sender, 100e18);
    }

    /// @notice Get the past votes for an account
    /// @return The past votes for the account
    function getPastVotes(address subject, uint256) public view returns (uint256) {
        return balanceOf(subject);
    }
}
