# euler-trap-poc

Drosera Trap proof of concept for the Euler Finance exploit — $197M, March 13 2023, block 16818057.

The goal: demonstrate a Trap that would have detected and halted this attack within the same block it began, deployed the way Drosera actually deploys Traps (no constructor arguments, account discovery via events).

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

The Trap subscribes to Euler's `Deposit / Borrow / Mint / DonateToReserves / Liquidate` events. Each block, Drosera Operators feed matching logs into the Trap; `collect()` extracts addresses from those logs (capped at 32), reads liquidity for each, and aggregates protocol-wide reserves and borrows. `shouldRespond()` evaluates four detection layers in order:

### 1. ReadFailure (operational)

Any market read reverts → fire immediately. A failed read is a signal in itself; silently substituting zero produces false negatives.

### 2. BadDebt (hard invariant)

For each account discovered in recent events: if `liabilityValue > collateralValue` → bad debt. Fires within 1 block of `donateToReserves()` dropping collateral below the liability threshold.

**Honest scope:** this is bad debt across DISCOVERED accounts only — accounts that emitted at least one of the subscribed events within the operator's recent-log window. Protocol-wide bad debt detection requires a protocol-level aggregator, which Euler v1 did not have. An attacker who never emits any monitored event remains invisible to this layer (in practice, the attack itself emits `Mint` and `DonateToReserves`, so it gets discovered — but this is a discovery dependency, not a guarantee).

### 3. ReserveVelocity (early warning)

`reserveGrowth >= 50%` over the sample window AND `totalBorrows` grew. Catches the donation+leverage fingerprint before the position is liquidated. Disabled when `base.totalReserves == 0` to avoid div-by-zero.

### 4. AbsoluteReserveSpike (zero-baseline coverage)

If `base.totalReserves == 0` and `curr.totalReserves >= ABSOLUTE_RESERVE_SPIKE` (1M units) while borrows grew. Closes the gap that ReserveVelocity opens when reserves start at zero.

---

## Sample window

`shouldRespond()` requires `data.length >= MIN_SAMPLE_SIZE` (= 5). The 5-block window calibrates the velocity threshold against Euler's normal interest accrual (~0.01% per block ≈ 5 BPS over 5 blocks vs. 5000 BPS = 50% trigger). Shorter windows would change what "50% growth" means; longer windows do not distort detection (verified in tests).

`drosera.toml` sets `block_sample_size = 5`. If you raise it, the threshold semantics still hold; lowering it below 5 is rejected by the Trap.

---

## Trigger payload (typed)

`shouldRespond()` returns an `abi.encode(uint8 triggerType, uint256 metric1, uint256 metric2, uint256 blockNumber)` payload. The response contract decodes the typed enum rather than parsing strings.

| triggerType | meaning              | metric1                | metric2                   |
|-------------|----------------------|------------------------|---------------------------|
| 1           | BadDebt              | sampledBadDebt (wei)   | unhealthyAccountCount     |
| 2           | ReserveVelocity      | reserveGrowthBps       | totalBorrows delta (wei)  |
| 3           | AbsoluteReserveSpike | curr.totalReserves     | totalBorrows delta (wei)  |
| 4           | ReadFailure          | 0                      | 0                         |

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

EulerTrapEdgeCases (reviewer-requested coverage):
  test_UnknownAttacker_DiscoveredViaEvents        — no whitelist; events drive discovery
  test_ReadFailure_TotalReserves_FiresReadFailureTrigger
  test_ReadFailure_TotalBorrows_FiresReadFailureTrigger
  test_ReadFailure_AccountLiquidity_FiresReadFailureTrigger
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
```

---

## Project structure

```
src/
  Trap.sol                          local mirror of Drosera abstract Trap
  EulerFinanceTrap.sol              the Trap — no constructor args, event-driven discovery
  interfaces/IEulerMarket.sol
  mocks/MockEulerMarket.sol         single-asset mock incl. withdraw / redeem / transferEToken
  response/EulerPauseResponse.sol   typed-payload response contract — pauses the market

test/
  helpers/TrapHarness.sol           shared setup: etches mock at Trap's constant address,
                                    feeds emitted logs back via setEventLogs()
  EulerExploitReproduction.t.sol    proves the exploit and the pause-blocks-exits claim
  EulerTrapDetection.t.sol          end-to-end detection + response authorization
  EulerTrapEdgeCases.t.sol          reviewer-requested edge cases
  EulerTrapFuzz.t.sol               property-based tests
```

---

## Run

```bash
git clone <this repo>
cd euler-trap-poc
forge install foundry-rs/forge-std
forge build
forge test -vvv
```

Requires [Foundry](https://getfoundry.sh).

---

## Deployment (Drosera)

1. Deploy `EulerPauseResponse(eulerMarket, trapManager)` — note the address.
2. Set `response_contract` in `drosera.toml` to that address.
3. `EULER_MARKET` inside `EulerFinanceTrap` is `address public constant`. For mainnet it points to Euler v1 (`0x2718...25d3`); for any other deployment, change the constant and rebuild.
4. Drosera Operators deploy `EulerFinanceTrap()` — no constructor arguments.

---

## Assumptions

- `EULER_MARKET` is a hardcoded constant. The Trap is purpose-built for one market; deploying for a different protocol means changing the constant and rebuilding (intentional — Drosera Traps cannot accept constructor arguments).
- Account discovery depends on Drosera Operators feeding matching event logs into the Trap each block. The Trap reads from `getEventLogs()` populated by `setEventLogs()` (Drosera-side responsibility).
- The mock is single-asset. Real Euler v1 was multi-market — the exploit played out across eDAI and edToken layers simultaneously. The core invariant (bad debt from `donateToReserves`) is the same; cross-market accounting is not modeled. Adding a `MockEulerController` + per-asset markets is the natural next step for a higher-fidelity simulation.
- Real Euler `mint()` routed through internal flash loans. The mock issues eTokens and dTokens directly, which produces identical post-state math.
- `collect()` is called on every block by Drosera Operators on a shadow fork — it does not submit transactions.

---

## What this does NOT protect against

- **Attacks where the attacker emits no monitored event.** If an attacker interacts with the market through a path that does not fire `Deposit/Borrow/Mint/DonateToReserves/Liquidate`, the address won't be discovered. The Euler exploit itself emits `Mint` and `DonateToReserves`, so it would be caught — but this is a discovery dependency, not an unconditional protocol-wide guarantee.
- **Attacks split across more than 32 distinct event-emitting addresses in the operator's log window** — discovery is capped at `MAX_ACCOUNTS = 32`. Tested up to 3 attackers; the cap is a memory-safety choice on a `view`-context array.
- **Attacks split across many small transactions over many blocks** that individually stay below the velocity threshold (the BadDebt layer still catches the eventual outcome).
- **Governance attacks, oracle manipulation, or any exploit path that does not produce bad debt or an abnormal reserve spike.**
- **The response is reactive, not preventive.** If the attack completes in a single transaction, the bad debt exists before the Trap fires. The Trap prevents the attacker from exiting (withdraw/redeem/transfer eTokens) with the stolen collateral — it does not undo the damage.

---

## Reference

- Exploit block: 16818057
- Date: March 13, 2023
- Protocol: Euler Finance v1
- Loss: ~$197M
- Root cause: `donateToReserves()` had no post-call health-factor check
- Drosera docs: https://dev.drosera.io
