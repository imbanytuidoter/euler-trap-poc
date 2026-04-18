# euler-trap-poc

Drosera Trap proof of concept for the Euler Finance exploit — $197M, March 13 2023, block 16818057.

The goal: show that a Drosera Trap would have detected and halted this attack within the same block it began.

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

Two invariants, ordered by detection speed:

### Invariant 1 — Hard (fires within 1 block)

```
getTotalBadDebt(trackedAccounts) > 0
```

The moment `donateToReserves()` drops collateral below the liability threshold, `getTotalBadDebt` returns non-zero. No liquidation required. Binary — either zero or attack.

### Invariant 2 — Velocity (early warning, pre-bad-debt)

```
reserveGrowth >= 50% AND totalBorrows grew in window
```

Catches the attack fingerprint before the position goes underwater. Euler's normal interest accrual is ~0.01% per block — a 50% reserve spike is unambiguous. This fires during the leverage+donation phase, before self-liquidation completes.

---

## Test results

```
forge test -vvv

Ran 14 tests across 3 suites: 14 passed, 0 failed

EulerExploitReproduction (proof the exploit works):
  [PASS] test_Attack_CreatesProtocolBadDebt
         Protocol bad debt: 71,250,000 * 1e18
  [PASS] test_DonateToReserves_HasNoSolvencyGuard
  [PASS] test_PausedMarket_BlocksAttackerExit

EulerTrapDetection (proof the Trap catches it):
  [PASS] test_Invariant1_BadDebt_TriggersShouldRespond
         [TRIGGERED] TRIGGERED: BadDebtInvariantBroke() — bad debt: 71250000...
  [PASS] test_Invariant2_ReserveVelocity_TriggersShouldRespond
         [TRIGGERED - EARLY WARNING] TRIGGERED: DonationAttackVelocityAnomaly()
         reserve growth BPS: 70000 — borrow increase: 100000000...
  [PASS] test_FullMitigation_AttackerCannotExit
         Market paused: true — Attacker successful exits: 0
  [PASS] test_NoFalsePositive_NormalOperation
  [PASS] test_InsufficientWindow_NoTrigger
  [PASS] test_ResponseAuthorization_OnlyTrapManager

EulerTrapFuzz (513 fuzz runs each):
  [PASS] testFuzz_NoFalsePositive_NormalBorrowAndDeposit
  [PASS] testFuzz_TriggerOnBadDebt
  [PASS] testFuzz_ReserveSpike_ThresholdBoundary
  [PASS] testFuzz_WindowSize_Robustness
  [PASS] test_EdgeCase_ZeroBaselineReserves_NoDivByZero
```

---

## Project structure

```
src/
  Trap.sol                          local mirror of Drosera abstract Trap
  EulerFinanceTrap.sol              main Trap — collect() + shouldRespond()
  interfaces/IEulerMarket.sol
  mocks/MockEulerMarket.sol         full economic simulation, no spoofed flags
  response/EulerPauseResponse.sol   response contract — pauses the market

test/
  EulerExploitReproduction.t.sol    proves the exploit is mechanically sound
  EulerTrapDetection.t.sol          proves the Trap detects and halts the attack
  EulerTrapFuzz.t.sol               property-based tests
```

---

## Run

```bash
git clone <this repo>
cd euler-trap-poc
forge install foundry-rs/forge-std
forge test -vvv
```

Requires [Foundry](https://getfoundry.sh).

---

## Assumptions

- `EULER_MARKET` points to a valid contract implementing `IEulerMarket`
- `trackedAccounts` includes all accounts involved in the attack. In this PoC the attacker addresses are known; in production this would require event-based tracking or monitoring all active borrowers
- The mock uses a single-asset model. Real Euler v1 was multi-market — the exploit played out across eDAI and edTokens simultaneously. The core invariant (bad debt from donateToReserves) is the same
- Real Euler `mint()` routed through internal flash loans. The mock issues eTokens and dTokens directly, which produces identical post-state math
- `collect()` is called on every block by Drosera Operators on a shadow fork — it does not submit transactions

---

## What this does NOT protect against

- Attacks from accounts not in `trackedAccounts`. If the attacker uses a fresh address not being monitored, Invariant 1 still fires (bad debt is protocol-wide), but Invariant 2 would miss the velocity signal from that account's borrows
- Attacks split across many small transactions over many blocks that individually stay below the 50% velocity threshold (Invariant 1 still catches the outcome)
- Governance attacks, oracle manipulation, or any exploit path that does not produce bad debt or an abnormal reserve spike
- The response is reactive, not preventive. If the attack completes in a single transaction, the bad debt exists before the Trap fires. The Trap prevents the attacker from exiting with the stolen collateral — it does not undo the damage

---

## Reference

- Exploit block: 16818057
- Date: March 13, 2023
- Protocol: Euler Finance v1
- Loss: ~$197M
- Root cause: `donateToReserves()` had no post-call health-factor check
- Drosera docs: https://dev.drosera.io
