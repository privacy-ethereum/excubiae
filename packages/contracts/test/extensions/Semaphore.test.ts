import { AbiCoder, Signer, ZeroAddress } from "ethers"
import { ethers } from "hardhat"
import { expect } from "chai"
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers"
import {
    BaseCheckerMock,
    BaseCheckerMock__factory,
    SemaphoreChecker,
    SemaphoreChecker__factory,
    SemaphoreCheckerFactory,
    SemaphoreCheckerFactory__factory,
    SemaphoreMock,
    SemaphoreMock__factory,
    SemaphorePolicy,
    SemaphorePolicy__factory,
    SemaphorePolicyFactory,
    SemaphorePolicyFactory__factory
} from "../../typechain-types"

/* eslint-disable @typescript-eslint/no-shadow */
describe("Semaphore", () => {
    describe("Checker", () => {
        async function deploySemaphoreCheckerFixture() {
            const [deployer, subject, target, notSubject]: Signer[] = await ethers.getSigners()
            const subjectAddress: string = await subject.getAddress()
            const notSubjectAddress: string = await notSubject.getAddress()

            const validGroupId = 0
            const invalidGroupId = 1

            const validProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 0n,
                message: ethers.toBigInt(subjectAddress),
                scope: BigInt(validGroupId),
                points: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }
            const invalidProverProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 0n,
                message: ethers.toBigInt(notSubjectAddress),
                scope: BigInt(validGroupId),
                points: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }
            const invalidGroupIdProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 0n,
                message: ethers.toBigInt(subjectAddress),
                scope: BigInt(invalidGroupId),
                points: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }
            const invalidProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 1n,
                message: ethers.toBigInt(subjectAddress),
                scope: BigInt(validGroupId),
                points: [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }

            const validEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    validProof.merkleTreeDepth,
                    validProof.merkleTreeRoot,
                    validProof.nullifier,
                    validProof.message,
                    validProof.scope,
                    validProof.points
                ]
            )
            const invalidProverEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    invalidProverProof.merkleTreeDepth,
                    invalidProverProof.merkleTreeRoot,
                    invalidProverProof.nullifier,
                    invalidProverProof.message,
                    invalidProverProof.scope,
                    invalidProverProof.points
                ]
            )
            const invalidGroupIdEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    invalidGroupIdProof.merkleTreeDepth,
                    invalidGroupIdProof.merkleTreeRoot,
                    invalidGroupIdProof.nullifier,
                    invalidGroupIdProof.message,
                    invalidGroupIdProof.scope,
                    invalidGroupIdProof.points
                ]
            )
            const invalidEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    invalidProof.merkleTreeDepth,
                    invalidProof.merkleTreeRoot,
                    invalidProof.nullifier,
                    invalidProof.message,
                    invalidProof.scope,
                    invalidProof.points
                ]
            )

            const groupIds = new Array(1)
            const nullifiers = new Array(2)
            const nullifiersValidities: boolean[] = new Array(2)

            groupIds[0] = validGroupId
            nullifiers[0] = validProof.nullifier
            nullifiers[1] = invalidProof.nullifier
            nullifiersValidities[0] = true
            nullifiersValidities[1] = false

            const SemaphoreMock: SemaphoreMock__factory = await ethers.getContractFactory("SemaphoreMock")
            const SemaphoreCheckerFactory: SemaphoreCheckerFactory__factory =
                await ethers.getContractFactory("SemaphoreCheckerFactory")

            const semaphoreMock: SemaphoreMock = await SemaphoreMock.deploy(groupIds, nullifiers, nullifiersValidities)
            const factory: SemaphoreCheckerFactory = await SemaphoreCheckerFactory.connect(deployer).deploy()

            const tx = await factory.deploy(await semaphoreMock.getAddress(), validGroupId)
            const receipt = await tx.wait()
            const event = SemaphoreCheckerFactory.interface.parseLog(
                receipt?.logs[0] as unknown as { topics: string[]; data: string }
            ) as unknown as {
                args: {
                    clone: string
                }
            }

            const checker: SemaphoreChecker = SemaphoreChecker__factory.connect(event.args.clone, deployer)

            return {
                semaphoreMock,
                checker,
                factory,
                deployer,
                target,
                subjectAddress,
                notSubjectAddress,
                validEvidence,
                invalidEvidence,
                invalidProverEvidence,
                invalidGroupIdEvidence,
                validGroupId,
                invalidGroupId
            }
        }

        describe("initialize", () => {
            it("deploy and initialize correctly", async () => {
                const { checker } = await loadFixture(deploySemaphoreCheckerFixture)

                expect(checker).to.not.eq(undefined)
                expect(await checker.initialized()).to.be.eq(true)
            })

            it("revert when already initialized", async () => {
                const { checker, deployer } = await loadFixture(deploySemaphoreCheckerFixture)

                await expect(checker.connect(deployer).initialize()).to.be.revertedWithCustomError(
                    checker,
                    "AlreadyInitialized"
                )
            })
        })

        describe("getAppendedBytes", () => {
            it("append bytes correctly", async () => {
                const { checker, semaphoreMock, validGroupId } = await loadFixture(deploySemaphoreCheckerFixture)

                const appendedBytes = await checker.getAppendedBytes.staticCall()

                const expectedBytes = AbiCoder.defaultAbiCoder()
                    .encode(["address", "uint256"], [await semaphoreMock.getAddress(), validGroupId])
                    .toLowerCase()

                expect(appendedBytes).to.equal(expectedBytes)
            })
        })

        describe("check", () => {
            it("reverts when scope prover is incorrect", async () => {
                const { checker, target, subjectAddress, invalidProverEvidence } =
                    await loadFixture(deploySemaphoreCheckerFixture)

                await expect(
                    checker.connect(target).check(subjectAddress, invalidProverEvidence)
                ).to.be.revertedWithCustomError(checker, "InvalidProver")
            })

            it("reverts when scope group id is incorrect", async () => {
                const { checker, target, subjectAddress, invalidGroupIdEvidence } =
                    await loadFixture(deploySemaphoreCheckerFixture)

                await expect(
                    checker.connect(target).check(subjectAddress, invalidGroupIdEvidence)
                ).to.be.revertedWithCustomError(checker, "InvalidGroup")
            })

            it("reverts when proof is invalid", async () => {
                const { checker, target, subjectAddress, invalidEvidence } =
                    await loadFixture(deploySemaphoreCheckerFixture)

                await expect(
                    checker.connect(target).check(subjectAddress, invalidEvidence)
                ).to.be.revertedWithCustomError(checker, "InvalidProof")
            })

            it("succeeds when valid", async () => {
                const { checker, target, subjectAddress, validEvidence } =
                    await loadFixture(deploySemaphoreCheckerFixture)

                expect(await checker.connect(target).check(subjectAddress, validEvidence)).to.be.equal(true)
            })
        })
    })

    describe("Policy", () => {
        async function deploySemaphorePolicyFixture() {
            const [deployer, subject, target, notSubject]: Signer[] = await ethers.getSigners()
            const subjectAddress: string = await subject.getAddress()
            const notSubjectAddress: string = await notSubject.getAddress()

            const validGroupId = 0
            const invalidGroupId = 1

            const validProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 0n,
                message: ethers.toBigInt(subjectAddress),
                scope: BigInt(validGroupId),
                points: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }
            const invalidProverProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 0n,
                message: ethers.toBigInt(notSubjectAddress),
                scope: BigInt(validGroupId),
                points: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }
            const invalidGroupIdProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 0n,
                message: ethers.toBigInt(subjectAddress),
                scope: BigInt(invalidGroupId),
                points: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }
            const invalidProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 1n,
                message: ethers.toBigInt(subjectAddress),
                scope: BigInt(validGroupId),
                points: [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }

            const validEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    validProof.merkleTreeDepth,
                    validProof.merkleTreeRoot,
                    validProof.nullifier,
                    validProof.message,
                    validProof.scope,
                    validProof.points
                ]
            )
            const invalidProverEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    invalidProverProof.merkleTreeDepth,
                    invalidProverProof.merkleTreeRoot,
                    invalidProverProof.nullifier,
                    invalidProverProof.message,
                    invalidProverProof.scope,
                    invalidProverProof.points
                ]
            )
            const invalidGroupIdEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    invalidGroupIdProof.merkleTreeDepth,
                    invalidGroupIdProof.merkleTreeRoot,
                    invalidGroupIdProof.nullifier,
                    invalidGroupIdProof.message,
                    invalidGroupIdProof.scope,
                    invalidGroupIdProof.points
                ]
            )
            const invalidEvidence = AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256[8]"],
                [
                    invalidProof.merkleTreeDepth,
                    invalidProof.merkleTreeRoot,
                    invalidProof.nullifier,
                    invalidProof.message,
                    invalidProof.scope,
                    invalidProof.points
                ]
            )

            const groupIds = new Array(1)
            const nullifiers = new Array(2)
            const nullifiersValidities: boolean[] = new Array(2)

            groupIds[0] = validGroupId
            nullifiers[0] = validProof.nullifier
            nullifiers[1] = invalidProof.nullifier
            nullifiersValidities[0] = true
            nullifiersValidities[1] = false

            const SemaphoreMock: SemaphoreMock__factory = await ethers.getContractFactory("SemaphoreMock")
            const SemaphoreCheckerFactory: SemaphoreCheckerFactory__factory =
                await ethers.getContractFactory("SemaphoreCheckerFactory")
            const SemaphorePolicyFactory: SemaphorePolicyFactory__factory =
                await ethers.getContractFactory("SemaphorePolicyFactory")
            const BaseCheckerMockFactory: BaseCheckerMock__factory = await ethers.getContractFactory("BaseCheckerMock")

            const semaphoreMock: SemaphoreMock = await SemaphoreMock.deploy(groupIds, nullifiers, nullifiersValidities)
            const checkerFactory: SemaphoreCheckerFactory = await SemaphoreCheckerFactory.connect(deployer).deploy()
            const policyFactory: SemaphorePolicyFactory = await SemaphorePolicyFactory.connect(deployer).deploy()
            const baseCheckerMock: BaseCheckerMock = await BaseCheckerMockFactory.connect(deployer).deploy()

            const checkerTx = await checkerFactory.deploy(await semaphoreMock.getAddress(), validGroupId)
            const checkerReceipt = await checkerTx.wait()
            const checkerEvent = SemaphoreCheckerFactory.interface.parseLog(
                checkerReceipt?.logs[0] as unknown as { topics: string[]; data: string }
            ) as unknown as {
                args: {
                    clone: string
                }
            }

            const checker: SemaphoreChecker = SemaphoreChecker__factory.connect(checkerEvent.args.clone, deployer)

            const policyTx = await policyFactory.deploy(await checker.getAddress())
            const policyReceipt = await policyTx.wait()
            const policyEvent = SemaphorePolicyFactory.interface.parseLog(
                policyReceipt?.logs[0] as unknown as { topics: string[]; data: string }
            ) as unknown as {
                args: {
                    clone: string
                }
            }

            const policy: SemaphorePolicy = SemaphorePolicy__factory.connect(policyEvent.args.clone, deployer)

            const policyWithCheckerMockTx = await policyFactory.deploy(await baseCheckerMock.getAddress())
            const policyWithCheckerMockReceipt = await policyWithCheckerMockTx.wait()
            const policyWithCheckerMockEvent = SemaphorePolicyFactory.interface.parseLog(
                policyWithCheckerMockReceipt?.logs[0] as unknown as { topics: string[]; data: string }
            ) as unknown as {
                args: {
                    clone: string
                }
            }

            const policyWithCheckerMock: SemaphorePolicy = SemaphorePolicy__factory.connect(
                policyWithCheckerMockEvent.args.clone,
                deployer
            )

            return {
                semaphoreMock,
                checker,
                policy,
                notSubject,
                policyWithCheckerMock,
                deployer,
                target,
                subjectAddress,
                notSubjectAddress,
                validEvidence,
                invalidEvidence,
                invalidProverEvidence,
                invalidGroupIdEvidence,
                validGroupId,
                invalidGroupId
            }
        }

        describe("initialize", () => {
            it("deploy and initialize correctly", async () => {
                const { policy } = await loadFixture(deploySemaphorePolicyFixture)

                expect(policy).to.not.eq(undefined)
                expect(await policy.initialized()).to.be.eq(true)
            })

            it("revert when already initialized", async () => {
                const { policy, deployer } = await loadFixture(deploySemaphorePolicyFixture)

                await expect(policy.connect(deployer).initialize()).to.be.revertedWithCustomError(
                    policy,
                    "AlreadyInitialized"
                )
            })
        })

        describe("getAppendedBytes", () => {
            it("append bytes correctly", async () => {
                const { policy, checker, deployer } = await loadFixture(deploySemaphorePolicyFixture)

                const appendedBytes = await policy.getAppendedBytes.staticCall()

                const expectedBytes = AbiCoder.defaultAbiCoder()
                    .encode(["address", "address"], [await deployer.getAddress(), await checker.getAddress()])
                    .toLowerCase()

                expect(appendedBytes).to.equal(expectedBytes)
            })
        })

        describe("trait", () => {
            it("returns correct value", async () => {
                const { policy } = await loadFixture(deploySemaphorePolicyFixture)

                expect(await policy.trait()).to.be.eq("Semaphore")
            })
        })

        describe("setTarget", () => {
            it("reverts when caller not owner", async () => {
                const { policy, notSubject, target } = await loadFixture(deploySemaphorePolicyFixture)

                await expect(
                    policy.connect(notSubject).setTarget(await target.getAddress())
                ).to.be.revertedWithCustomError(policy, "OwnableUnauthorizedAccount")
            })

            it("reverts when zero address", async () => {
                const { policy, deployer } = await loadFixture(deploySemaphorePolicyFixture)

                await expect(policy.connect(deployer).setTarget(ZeroAddress)).to.be.revertedWithCustomError(
                    policy,
                    "ZeroAddress"
                )
            })

            it("sets target correctly", async () => {
                const { policy, target } = await loadFixture(deploySemaphorePolicyFixture)
                const targetAddress = await target.getAddress()
                const tx = await policy.setTarget(targetAddress)
                const receipt = await tx.wait()
                const event = policy.interface.parseLog(
                    receipt?.logs[0] as unknown as { topics: string[]; data: string }
                ) as unknown as {
                    args: {
                        guarded: string
                    }
                }

                expect(receipt?.status).to.eq(1)
                expect(event.args.guarded).to.eq(targetAddress)
            })

            it("reverts when already set", async () => {
                const { policy, target } = await loadFixture(deploySemaphorePolicyFixture)
                const targetAddress = await target.getAddress()

                await policy.setTarget(targetAddress)

                await expect(policy.setTarget(targetAddress)).to.be.revertedWithCustomError(policy, "TargetAlreadySet")
            })
        })

        describe("enforce", () => {
            it("reverts when scope prover is incorrect", async () => {
                const { policy, checker, target, subjectAddress, invalidProverEvidence } =
                    await loadFixture(deploySemaphorePolicyFixture)

                await policy.setTarget(await target.getAddress())

                await expect(
                    policy.connect(target).enforce(subjectAddress, invalidProverEvidence)
                ).to.be.revertedWithCustomError(checker, "InvalidProver")
            })

            it("reverts when scope group id is incorrect", async () => {
                const { policy, checker, target, subjectAddress, invalidGroupIdEvidence } =
                    await loadFixture(deploySemaphorePolicyFixture)

                await policy.setTarget(await target.getAddress())

                await expect(
                    policy.connect(target).enforce(subjectAddress, invalidGroupIdEvidence)
                ).to.be.revertedWithCustomError(checker, "InvalidGroup")
            })

            it("reverts when proof is invalid", async () => {
                const { policy, checker, target, subjectAddress, invalidEvidence } =
                    await loadFixture(deploySemaphorePolicyFixture)

                await policy.setTarget(await target.getAddress())

                await expect(
                    policy.connect(target).enforce(subjectAddress, invalidEvidence)
                ).to.be.revertedWithCustomError(checker, "InvalidProof")
            })

            it("enforces successfully", async () => {
                const { policy, target, subjectAddress, validEvidence } =
                    await loadFixture(deploySemaphorePolicyFixture)
                const targetAddress = await target.getAddress()

                await policy.setTarget(await target.getAddress())

                const tx = await policy.connect(target).enforce(subjectAddress, validEvidence)
                const receipt = await tx.wait()
                const event = policy.interface.parseLog(
                    receipt?.logs[0] as unknown as { topics: string[]; data: string }
                ) as unknown as {
                    args: {
                        subject: string
                        guarded: string
                        evidence: string
                    }
                }

                expect(receipt?.status).to.eq(1)
                expect(event.args.subject).to.eq(subjectAddress)
                expect(event.args.guarded).to.eq(targetAddress)
                expect(event.args.evidence).to.eq(validEvidence)
            })

            it("reverts when already spent nullifier", async () => {
                const { policy, target, subjectAddress, validEvidence } =
                    await loadFixture(deploySemaphorePolicyFixture)

                await policy.setTarget(await target.getAddress())

                await policy.connect(target).enforce(subjectAddress, validEvidence)

                await expect(
                    policy.connect(target).enforce(subjectAddress, validEvidence)
                ).to.be.revertedWithCustomError(policy, "AlreadyEnforced")
            })

            it("reverts when check fails", async () => {
                const { policyWithCheckerMock, target, subjectAddress, validEvidence } =
                    await loadFixture(deploySemaphorePolicyFixture)

                await policyWithCheckerMock.setTarget(await target.getAddress())

                await expect(
                    policyWithCheckerMock.connect(target).enforce(subjectAddress, validEvidence)
                ).to.be.revertedWithCustomError(policyWithCheckerMock, "UnsuccessfulCheck")
            })
        })
    })

    describe("Mock", () => {
        it("deploy and stubs correctly for coverage", async () => {
            const [deployer]: Signer[] = await ethers.getSigners()
            const deployerAddress: string = await deployer.getAddress()

            const validGroupId = 0

            const validProof = {
                merkleTreeDepth: 1n,
                merkleTreeRoot: 0n,
                nullifier: 0n,
                message: ethers.toBigInt(deployerAddress),
                scope: BigInt(validGroupId),
                points: [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]
            }

            const groupIds = new Array(1)
            const nullifiers = new Array(1)
            const nullifiersValidities: boolean[] = new Array(1)

            groupIds[0] = validGroupId
            nullifiers[0] = validProof.nullifier
            nullifiersValidities[0] = true

            const SemaphoreMock: SemaphoreMock__factory = await ethers.getContractFactory("SemaphoreMock")
            const semaphoreMock: SemaphoreMock = await SemaphoreMock.deploy(groupIds, nullifiers, nullifiersValidities)

            // test stubs.
            expect(await semaphoreMock["createGroup()"]()).to.equal(0)
            expect(await semaphoreMock["createGroup(address)"](deployerAddress)).to.equal(0)
            expect(await semaphoreMock["createGroup(address,uint256)"](deployerAddress, 0)).to.equal(0)

            await semaphoreMock.updateGroupAdmin(0, deployerAddress)
            await semaphoreMock.acceptGroupAdmin(0)
            await semaphoreMock.updateGroupMerkleTreeDuration(0, 0)
            await semaphoreMock.addMember(0, 0)

            const dummy = [validGroupId]

            await semaphoreMock.addMembers(0, dummy)
            await semaphoreMock.updateMember(0, 0, 0, dummy)
            await semaphoreMock.removeMember(0, 0, dummy)
            await semaphoreMock.validateProof(0, validProof)
        })
    })
})
