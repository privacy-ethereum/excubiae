// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BasePolicy } from "../../policy/BasePolicy.sol";

/// @title ZupassPolicy
/// @notice This contract enforces Zupass validation.
/// by requiring new voters to own a certain Zupass event ticket
contract ZupassPolicy is BasePolicy {
    /// @notice a mapping of ticket IDs to whether they have been used
    mapping(uint256 => bool) public enforcedTickets;

    /// @notice Create a new instance of ZupassPolicy
    // solhint-disable-next-line no-empty-blocks
    constructor() payable { }

    /// @notice Enforces a user only if they have the Zupass event ticket
    /// @param _subject The user's Ethereum address.
    /// @param _evidence The ABI-encoded proof and public signals.
    function _enforce(address _subject, bytes calldata _evidence) internal override {
        // Decode the given _data bytes
        (,,, uint256[38] memory pubSignals) =
            abi.decode(_evidence, (uint256[2], uint256[2][2], uint256[2], uint256[38]));

        // Ticket ID is stored at index 0
        uint256 ticketId = pubSignals[0];

        if (enforcedTickets[ticketId]) {
            revert AlreadyEnforced();
        }

        enforcedTickets[ticketId] = true;

        super._enforce(_subject, _evidence);
    }

    /// @notice Get the trait of the Policy
    /// @return The type of the Policy
    function trait() public pure override returns (string memory) {
        return "Zupass";
    }
}
