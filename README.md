# euler-trap-poc

Drosera Trap proof of concept for the Euler Finance exploit — $197M, March 13 2023, block 16818057.

This is a **mock-production** demonstration of a Drosera Trap that detects Euler-style bad debt and reserve-donation anomalies on a single configured market.

It does **not** claim to interrupt an already-atomic transaction during execution. It detects once a broken invariant becomes observable on-chain and contains the follow-on exits.

---

## The exploit

Euler Finance v1 had a missing health-factor check in `donateToReserves()`. The attack:

1. Build a max-leverage position via `mint()` — eTokens and dTokens issued atomically, single post-state solvency check
2. Call `donateToReserves()` to burn collateral with **no solvency check** — position immediately underwater
3. Second EOA liquidates the first — receives collateral + 20% bonus
4. Protocol is left with bad debt; attacker keeps the extracted collateral

The root cause is one missing line: a health-factor check after `donateToReserves()`.

---

## How the Trap detects it

The Trap subscribes to Euler's `Deposit / Borrow / Mint / DonateToReserves / Liquidate` events. Each block, Drosera Operators feed matching logs into the Trap; `collect()` walks them in priority order, reads liquidity for each discovered account, and aggregates protocol-wide reserves and borrows. `shouldRespond()` then evaluates three actionable detection layers:

### 1. BadDebt (hard invariant)

For each discovered account: if `liabilityValue > collateralValue` → bad debt. Fires once `donateToReserves()` has dropped collateral below the liability threshold and the position is observable.

**Honest scope:** this is bad debt across DISCOVERED accounts only — accounts that emitted at least one of the subscribed events within the operator's recent-log window. Protocol-wide bad debt detection requires a protocol-level aggregator, which Euler v1 did not have.

### 2. ReserveVelocity (early warning)

`reserveGrowth >= 50%` over the sample window AND `totalBorrows` grew. Catches the donation+leverage fingerprint before the position is liquidated. Disabled when `base.totalReserves == 0` (avoid div-by-zero — covered by the next layer).

### 3. AbsoluteReserveSpike (zero-baseline coverage)

If `base.totalReserves == 0` and `curr.totalReserves >= ABSOLUTE_RESERVE_SPIKE` (1M units) while borrows grew. Closes the gap that ReserveVelocity opens when reserves start at zero.

---

## Read-failure policy

Read failures (a market read reverts) are treated as **alert-only**, not auto-pause material. The justification: an RPC blip or a malformed external call should not be enough to halt the protocol on the operator quorum.

The split:

- `shouldRespond()` ignores read-failure samples and returns `(false, "")`. No auto-pause.
- `shouldAlert()` emits a `ReadFailureAlertOnly` payload that operators / humans can subscribe to.
- `EulerPauseResponse.respond()` rejects `ReadFailureAlertOnly` with `UnknownTriggerType`. Even if the payload reaches the response contract by mistake, it cannot pause the market.

---

## Discovery cap and prioritization

Account discovery is bounded at `MAX_ACCOUNTS = 32` per block window — a memory-safety cap on the in-memory accumulator.

To stop a low-signal `Deposit` spam from filling the cap and crowding out the actual offender, discovery walks signatures in this order:

1. `DonateToReserves` account
2. `Liquidate` violator
3. `Mint` account
4. `Borrow` account
5. `Deposit` account
6. `Liquidate` liquidator (lowest priority — the responder, not the offender)

This guarantees that high-risk accounts get their cap slots before the lower-signal Deposit-only spam.

---

## Sample window

`shouldRespond()` requires `data.length >= MIN_SAMPLE_SIZE` (= 5). The 5-block window calibrates the velocity threshold against Euler's normal interest accrual (~0.01% per block ≈ 5 BPS over 5 blocks vs. 5000 BPS = 50% trigger). Shorter windows would change what "50% growth" means; longer windows do not distort detection (verified in tests).

`drosera.toml.example` sets `block_sample_size = 5`. Raising it is fine; lowering it below 5 is rejected by the Trap.

---

## Trigger payload (typed)

`shouldRespond()` and `shouldAlert()` return `abi.encode(uint8 triggerType, uint256 metric1, uint256 metric2, uint256 blockNumber)`. The response contract decodes the typed enum rather than parsing strings.

| triggerType | meaning              | metric1                | metric2                   | accepted by response |
|-------------|----------------------|------------------------|---------------------------|----------------------|
| 1           | BadDebt              | sampledBadDebt (wei)   | unhealthyAccountCount     | yes                  |
| 2           | ReserveVelocity      | reserveGrowthBps       | totalBorrows delta (wei)  | yes                  |
| 3           | AbsoluteReserveSpike | curr.totalReserves     | totalBorrows delta (wei)  | yes                  |
| 4           | ReadFailureAlertOnly | 0                      | 0                         | **no** (alert-only)  |

`EulerFinanceTrap.decodeAlertOutput(bytes)` is exposed for off-chain consumers.

---

## Test results

```
forge test -vvv

EulerExploitReproduction (proof the exploit works):
  test_Attack_CreatesProtocolBadDebt
  test_DonateToReserves_HasNoSolvencyGuard
  test_PausedMarket_BlocksAttackerExits           — withdraw / redeem / transferEToken all blocked
  test_UnpausedMarket_AllowsExits                 — sanity: those paths work pre-pause

EulerTrapDetection (proof the Trap catches it):
  test_NoFalsePositive_NormalOperation
  test_Invariant1_BadDebt_TriggersShouldRespond
  test_Invariant2_ReserveVelocity_TriggersShouldRespond
  test_FullMitigation_AttackerCannotExit          — pause blocks withdraw + redeem + transferEToken
  test_InsufficientWindow_NoTrigger               — < MIN_SAMPLE_SIZE (= 5) rejected
  test_ResponseAuthorization_OnlyTrapManager
  test_DoubleResponse_RevertsAlreadyPaused        — second respond() after pause reverts
  test_MalformedPayload_Reverts                   — invalid size / unknown trigger type rejected
  test_ResponseRejectsReadFailureAlertOnly        — non-actionable trigger refused at the response
  test_ResponseRejectsOversizedPayload            — exact 4*32 byte length enforced

EulerTrapEdgeCases (mock-production coverage):
  test_UnknownAttacker_DiscoveredViaEvents        — no whitelist; events drive discovery
  test_DiscoveryPriority_DonationAccountSurvivesDepositSpam
                                                  — 40 deposit spammers can't crowd out the donor
  test_ReadFailure_TotalReserves_AlertsOnly       — shouldRespond=false, shouldAlert=true
  test_ReadFailure_TotalBorrows_AlertsOnly
  test_ReadFailure_AccountLiquidity_AlertsOnly
  test_MalformedCollectSample_DoesNotRevertShouldRespond
                                                  — garbage bytes can't crash the trap
  test_ZeroBaseline_AbsoluteReserveSpike_Triggers
  test_ZeroBaseline_BelowAbsoluteThreshold_NoTrigger
  test_LongerWindow_DoesNotDistortDetection       — 10-block window still fires
  test_AttackSplit_AcrossMultipleAddresses        — 3 attackers, aggregated bad debt
  test_AttackSplit_AcrossMultipleSmallerDonations — 5 sub-threshold donations summed
  test_LegitimateDonation_WithoutBorrowGrowth_NoFalsePositive
  test_BorrowGrowth_WithoutReserveSpike_NoFalsePositive

EulerTrapFuzz (512 fuzz runs each):
  testFuzz_NoFalsePositive_NormalBorrowAndDeposit
  testFuzz_TriggerOnBadDebt
  testFuzz_ReserveSpike_ThresholdBoundary
  testFuzz_WindowSize_Robustness
  test_EdgeCase_ZeroBaselineReserves_NoDivByZero

32 / 32 passing.
```

---

## Project structure

```
src/
  EulerFinanceTrap.sol              the Trap — no constructor args, event-driven discovery
  interfaces/IEulerMarket.sol
  mocks/MockEulerMarket.sol         single-asset mock incl. withdraw / redeem / transferEToken
  response/EulerPauseResponse.sol   typed-payload response contract — pauses the market

test/
  helpers/TrapHarness.sol           shared setup: etches the mock at the Trap's constant address,
                                    feeds emitted logs back via setEventLogs()
  EulerExploitReproduction.t.sol    proves the exploit and the pause-blocks-exits claim
  EulerTrapDetection.t.sol          end-to-end detection + response authorization
  EulerTrapEdgeCases.t.sol          discovery / read-failure / malformed-input coverage
  EulerTrapFuzz.t.sol               property-based tests
```

---

## Dependencies

- [`drosera-network/contracts`](https://github.com/drosera-network/contracts) — canonical `Trap` base, imported as `drosera-contracts/Trap.sol` (remapped in `foundry.toml`).
  Pinned at commit `3726d82f291914c79308fa458c95a556cc7debb0`.
- [`foundry-rs/forge-std`](https://github.com/foundry-rs/forge-std) — test framework.

---

## Run

```bash
git clone <this repo>
cd euler-trap-poc
forge install drosera-network/contracts
forge install foundry-rs/forge-std
forge build
forge test -vvv
```

Requires [Foundry](https://getfoundry.sh).

---

## Deployment (Drosera)

1. Deploy `EulerPauseResponse(EULER_MARKET, DROSERA_TRAP_MANAGER)` — note the address.
2. Copy `drosera.toml.example` to `drosera.toml` and fill in:
   - `response_contract` = the deployed response-contract address
   - `ethereum_rpc`, `drosera_rpc`, `eth_chain_id`, `drosera_address`
3. `EULER_MARKET` inside `EulerFinanceTrap` is `address public constant`. For mainnet it points to Euler v1 (`0x2718…25d3`); for any other deployment, change the constant and rebuild.
4. `forge build`
5. `drosera dryrun`
6. `drosera apply` — Drosera Operators deploy `EulerFinanceTrap()` with no constructor arguments.

---

## Mock-production scope

- `EULER_MARKET` is a hardcoded constant. The Trap is purpose-built for one market; deploying for a different protocol means changing the constant and rebuilding (intentional — Drosera Traps cannot accept constructor arguments).
- Account discovery depends on Drosera Operators feeding matching event logs into the Trap each block. The Trap reads from `getEventLogs()` populated by `setEventLogs()` (Drosera-side responsibility).
- The mock emits simplified Euler-style events (`Deposit`, `Borrow`, `Mint`, `DonateToReserves`, `Liquidate`). Real Euler v1 deployment uses the same event signatures and indexed fields, so the discovery logic transfers as-is. This repository proves the event-discovery pattern against a mock; it does not attest to the exact runtime behaviour of the real Euler contracts.
- The mock is single-asset. Real Euler v1 was multi-market — the exploit played out across eDAI and edToken layers simultaneously. The core invariant (bad debt from `donateToReserves`) is the same; cross-market accounting is not modeled. Adding a `MockEulerController` + per-asset markets is the natural next step for a higher-fidelity simulation.
- Real Euler `mint()` routed through internal flash loans. The mock issues eTokens and dTokens directly, which produces identical post-state math.
- `collect()` is called on every block by Drosera Operators on a shadow fork — it does not submit transactions.

---

## What this does NOT protect against

- **Attacks where the attacker emits no monitored event.** If an attacker interacts with the market through a path that does not fire `Deposit / Borrow / Mint / DonateToReserves / Liquidate`, the address won't be discovered. The Euler exploit itself emits `Mint` and `DonateToReserves`, so it would be caught — but this is a discovery dependency, not an unconditional protocol-wide guarantee.
- **Attacks that rely on more than 32 distinct event-emitting addresses crowding out the offender.** Discovery is capped at `MAX_ACCOUNTS = 32` and prioritized so Donate / Liquidate-violator / Mint slots fill first; a sufficiently large mixed-signature spam can still dilute coverage.
- **Attacks split across many small transactions over many blocks** that individually stay below the velocity threshold (the BadDebt layer still catches the eventual outcome).
- **Governance attacks, oracle manipulation, or any exploit path that does not produce bad debt or an abnormal reserve spike.**
- **The response is reactive, not preventive.** If the attack completes in a single transaction, the bad debt exists before the Trap fires. The Trap detects once observable and prevents the attacker from exiting (withdraw / redeem / transfer eTokens) with the stolen collateral — it does not undo the damage.

---

## Reference

- Exploit block: 16818057
- Date: March 13, 2023
- Protocol: Euler Finance v1
- Loss: ~$197M
- Root cause: `donateToReserves()` had no post-call health-factor check
- Drosera docs: https://dev.drosera.io
