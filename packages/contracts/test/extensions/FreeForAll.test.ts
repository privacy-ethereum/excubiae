import { expect } from "chai"
import { AbiCoder, Signer, ZeroAddress } from "ethers"
import { ethers } from "hardhat"

import { FreeForAllPolicy__factory as FreeForAllPolicyFactory, FreeForAllPolicy } from "../../typechain-types"

describe("FreeForAll", () => {
    let policy: FreeForAllPolicy
    let deployer: Signer
    let subject: Signer
    let target: Signer
    let notSubject: Signer

    before(async () => {
        ;[deployer, subject, target, notSubject] = await ethers.getSigners()

        const CheckerFactory = await ethers.getContractFactory("FreeForAllCheckerFactory")
        const checkerFactory = await CheckerFactory.connect(deployer).deploy()

        const PolicyFactory = await ethers.getContractFactory("FreeForAllPolicyFactory")
        const policyFactory = await PolicyFactory.connect(deployer).deploy()

        const checkerTx = await checkerFactory.deploy()
        const checkerReceipt = await checkerTx.wait()

        const checkerDeployEvent = CheckerFactory.interface.parseLog(
            checkerReceipt?.logs[0] as unknown as { topics: string[]; data: string }
        ) as unknown as {
            args: {
                clone: string
            }
        }

        const policyTx = await policyFactory.deploy(checkerDeployEvent.args.clone)
        const policyReceipt = await policyTx.wait()
        const policyEvent = PolicyFactory.interface.parseLog(
            policyReceipt?.logs[0] as unknown as { topics: string[]; data: string }
        ) as unknown as {
            args: {
                clone: string
            }
        }

        policy = FreeForAllPolicyFactory.connect(policyEvent.args.clone, deployer)
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
            expect(await policy.trait()).to.eq("FreeForAll")
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

        it("should enforce a user if the function is called with the valid data", async () => {
            const tx = await policy.connect(target).enforce(subject, AbiCoder.defaultAbiCoder().encode([], []))

            const receipt = await tx.wait()

            expect(receipt?.status).to.eq(1)
        })

        it("should prevent enforcing the same account twice", async () => {
            await expect(
                policy.connect(target).enforce(subject, AbiCoder.defaultAbiCoder().encode([], []))
            ).to.be.revertedWithCustomError(policy, "AlreadyEnforced")
        })
    })
})
