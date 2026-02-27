import { expect } from "chai"
import { Signer, ZeroAddress, toBeArray } from "ethers"
import { ethers } from "hardhat"

import {
    EASChecker__factory as EASCheckerFactory,
    EASPolicy__factory as EASPolicyFactory,
    EASChecker,
    EASPolicy,
    MockEAS
} from "../../typechain-types"

describe("EAS", () => {
    let policy: EASPolicy
    let checker: EASChecker
    let mockEAS: MockEAS
    let deployer: Signer
    let subject: Signer
    let target: Signer
    let notSubject: Signer

    const schema = "0xfdcfdad2dbe7489e0ce56b260348b7f14e8365a8a325aef9834818c00d46b31b"

    const revokedAttestation = "0x0000000000000000000000000000000000000000000000000000000000000001"
    const invalidSchemaAttestation = "0x0000000000000000000000000000000000000000000000000000000000000002"
    const invalidRecipientAttestation = "0x0000000000000000000000000000000000000000000000000000000000000003"
    const invalidAttesterAttestation = "0x0000000000000000000000000000000000000000000000000000000000000004"
    // valid attestation
    const attestation = "0x0000000000000000000000000000000000000000000000000000000000000000"
    const anotherAttestation = "0x0000000000000000000000000000000000000000000000000000000000000005"

    before(async () => {
        ;[deployer, subject, target, notSubject] = await ethers.getSigners()

        const subjectAddress = await subject.getAddress()
        const mockEASFactory = await ethers.getContractFactory("MockEAS")
        mockEAS = await mockEASFactory.connect(deployer).deploy(subjectAddress, toBeArray(schema), subjectAddress)
        const mockEASAddress = await mockEAS.getAddress()

        const CheckerFactory = await ethers.getContractFactory("EASCheckerFactory")
        const checkerFactory = await CheckerFactory.connect(deployer).deploy()

        const PolicyFactory = await ethers.getContractFactory("EASPolicyFactory")
        const policyFactory = await PolicyFactory.connect(deployer).deploy()

        const checkerTx = await checkerFactory.deploy(mockEASAddress, subjectAddress, toBeArray(schema))
        const checkerReceipt = await checkerTx.wait()

        const checkerDeployEvent = CheckerFactory.interface.parseLog(
            checkerReceipt?.logs[0] as unknown as { topics: string[]; data: string }
        ) as unknown as {
            args: {
                clone: string
            }
        }

        checker = EASCheckerFactory.connect(checkerDeployEvent.args.clone, deployer)

        const policyTx = await policyFactory.deploy(checkerDeployEvent.args.clone)
        const policyReceipt = await policyTx.wait()
        const policyEvent = PolicyFactory.interface.parseLog(
            policyReceipt?.logs[0] as unknown as { topics: string[]; data: string }
        ) as unknown as {
            args: {
                clone: string
            }
        }

        policy = EASPolicyFactory.connect(policyEvent.args.clone, deployer)
    })

    describe("Deployment", () => {
        it("should be deployed correctly", () => {
            expect(policy).to.not.eq(undefined)
        })
    })

    describe("Policy", () => {
        it("should set guarded target correctly", async () => {
            await policy.setTarget(target).then((tx) => tx.wait())

            expect(await policy.guarded()).to.eq(target)
        })

        it("should return trait properly", async () => {
            expect(await policy.trait()).to.eq("EAS")
        })

        it("should fail to set guarded target when the caller is not the owner", async () => {
            await expect(policy.connect(notSubject).setTarget(target)).to.be.revertedWithCustomError(
                policy,
                "OwnableUnauthorizedAccount"
            )
        })

        it("should fail to set guarded target when the target is not valid", async () => {
            await expect(policy.setTarget(ZeroAddress)).to.be.revertedWithCustomError(policy, "ZeroAddress")
        })

        it("should throw when the attestation is not owned by the caller", async () => {
            await expect(
                policy.connect(target).enforce(subject, invalidRecipientAttestation)
            ).to.be.revertedWithCustomError(checker, "NotYourAttestation")
        })

        it("should throw when the attestation has been revoked", async () => {
            await expect(policy.connect(target).enforce(subject, revokedAttestation)).to.be.revertedWithCustomError(
                checker,
                "AttestationRevoked"
            )
        })

        it("should throw when the attestation schema is not the one expected by the policy", async () => {
            await expect(
                policy.connect(target).enforce(subject, invalidSchemaAttestation)
            ).to.be.revertedWithCustomError(checker, "InvalidSchema")
        })

        it("should throw when the attestation is not signed by the attestation owner", async () => {
            await expect(
                policy.connect(target).enforce(subject, invalidAttesterAttestation)
            ).to.be.revertedWithCustomError(checker, "AttesterNotTrusted")
        })

        it("should enforce a user if the function is called with the valid data", async () => {
            const tx = await policy.connect(target).enforce(subject, attestation)

            const receipt = await tx.wait()

            expect(receipt?.status).to.eq(1)
        })

        it("should prevent enforcing twice with same subject and same attestation", async () => {
            await expect(policy.connect(target).enforce(subject, attestation)).to.be.revertedWithCustomError(
                policy,
                "AlreadyEnforced"
            )
        })

        it("should prevent enforcing twice with same subject and different attestation", async () => {
            await expect(policy.connect(target).enforce(subject, anotherAttestation)).to.be.revertedWithCustomError(
                policy,
                "AlreadyEnforced"
            )
        })
    })
})
