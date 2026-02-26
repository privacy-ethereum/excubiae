// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";

/// @title SemaphoreMock
/// @notice Mock implementation of the ISemaphore interface for testing purposes.
/// @dev Simulates Semaphore contract behavior with predefined mocked proofs and groups.
contract SemaphoreMock is ISemaphore {
    /// @notice Mapping to track mocked groups by their IDs.
    mapping(uint256 => bool) public mockedGroups;

    /// @notice Mapping to track mocked proofs by their unique nullifiers.
    mapping(uint256 => bool) private mockedProofs;

    /// @notice Counter to track the number of mocked groups created.
    uint256 public groupCounter;

    /// @notice Initializes the mock contract with predefined groups and proofs.
    /// @param _groupIds Array of group IDs managed by the mock contract.
    /// @param _nullifiers Array of nullifiers representing mocked proofs.
    /// @param _validities Array of booleans indicating validity of the corresponding proofs.
    constructor(uint256[] memory _groupIds, uint256[] memory _nullifiers, bool[] memory _validities) {
        for (uint256 i = 0; i < _groupIds.length; i++) {
            mockedGroups[_groupIds[i]] = true;
            groupCounter++;
        }

        for (uint256 i = 0; i < _nullifiers.length; i++) {
            mockedProofs[_nullifiers[i]] = _validities[i];
        }
    }

    function verifyProof(uint256 scope, SemaphoreProof calldata proof) external view returns (bool) {
        return mockedGroups[scope] && mockedProofs[proof.nullifier];
    }

    /// @notice Stub functions required to comply with the ISemaphore interface.
    function createGroup() external pure override returns (uint256) {
        return 0;
    }

    function createGroup(address) external pure override returns (uint256) {
        return 0;
    }

    function createGroup(address, uint256) external pure override returns (uint256) {
        return 0;
    }

    function updateGroupAdmin(uint256, address) external override {}

    function acceptGroupAdmin(uint256) external override {}

    function updateGroupMerkleTreeDuration(uint256, uint256) external override {}

    function addMember(uint256, uint256) external override {}

    function addMembers(uint256, uint256[] calldata) external override {}

    function updateMember(uint256, uint256, uint256, uint256[] calldata) external override {}

    function removeMember(uint256, uint256, uint256[] calldata) external override {}

    function validateProof(uint256, SemaphoreProof calldata) external override {}
}
