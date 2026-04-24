// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Trap.sol";
import "./interfaces/IEulerMarket.sol";

// Drosera Trap — Euler Finance donateToReserves() exploit
// March 13 2023, block 16818057, ~$197M
//
// Invariant 1 (hard): totalBadDebt == 0
//   Signal: getTotalBadDebt(trackedAccounts) > 0
//   Fires within 1 block of donateToReserves() dropping collateral below liabilities.
//   No threshold — any non-zero value is a trigger.
//
// Invariant 2 (velocity): reserve spike with concurrent borrow growth
//   Signal: reserveGrowth >= 50% over the sample window AND totalBorrows increased
//   Fires during the leverage+donation phase, before liquidation completes.
//
// Sample window: 5 blocks
//   Invariant 1 needs 2 blocks (current state vs. any clean prior snapshot).
//   Invariant 2 uses 5 to separate the attack rate from normal interest accrual
//   (~0.01%/block expected vs. 50%+ observed).

contract EulerFinanceTrap is Trap {

    address public immutable EULER_MARKET;
    address[] public trackedAccounts;

    // 50% reserve growth threshold over the sample window.
    // Normal Euler interest accrual is ~0.01%/block (~5 BPS over 5 blocks).
    // A 5000 BPS jump in the same window is ~1000x the expected rate.
    uint256 public constant RESERVE_SPIKE_BPS = 5_000;
    uint256 private constant BPS = 10_000;

    constructor(address market, address[] memory accounts) {
        EULER_MARKET    = market;
        trackedAccounts = accounts;
    }

    struct CollectOutput {
        uint256 totalBadDebt;
        uint256 totalReserves;
        uint256 totalBorrows;
        uint256 blockNumber;
    }

    // Reads market state each block. Each field maps to a detection signal.
    // External calls are wrapped in try/catch — if a read reverts the field
    // defaults to zero and collect() returns a safe zero-state snapshot.
    function collect() external view override returns (bytes memory) {
        IEulerMarket market = IEulerMarket(EULER_MARKET);

        uint256 badDebt;
        uint256 reserves;
        uint256 borrows;

        // [TRAP LINE A] donateToReserves() → eTokens drop → liab > col
        // → getTotalBadDebt() returns non-zero → primary detection signal
        try market.getTotalBadDebt(trackedAccounts) returns (uint256 bd) {
            badDebt = bd;
        } catch {}

        try market.totalReserves() returns (uint256 r) { reserves = r; } catch {}
        try market.totalBorrows()  returns (uint256 b) { borrows  = b; } catch {}

        return abi.encode(CollectOutput({
            totalBadDebt  : badDebt,
            totalReserves : reserves,
            totalBorrows  : borrows,
            blockNumber   : block.number
        }));
    }

    // Called with data[] newest-first. data[0] = current block, data[4] = 4 blocks ago.
    function shouldRespond(bytes[] calldata data)
        external pure override
        returns (bool, bytes memory)
    {
        return _evaluate(data);
    }

    function shouldAlert(bytes[] calldata data)
        external pure override
        returns (bool, bytes memory)
    {
        return _evaluate(data);
    }

    function _evaluate(bytes[] calldata data)
        internal pure
        returns (bool, bytes memory)
    {
        if (data.length < 2) return (false, bytes(""));

        CollectOutput memory curr = abi.decode(data[0],              (CollectOutput));
        CollectOutput memory base = abi.decode(data[data.length - 1],(CollectOutput));

        // Invariant 1: bad debt == 0
        // [EXPLOIT LINE] donateToReserves(100M) collapses eToken balance
        //   → liabilities exceed collateral → getTotalBadDebt() > 0
        // [TRAP LINE A] binary — any non-zero bad debt triggers response
        if (curr.totalBadDebt > 0) {
            return (true, abi.encode(
                "TRIGGERED: BadDebtInvariantBroke()",
                curr.totalBadDebt,
                curr.blockNumber
            ));
        }

        // Invariant 2: reserve velocity + borrow growth
        // [EXPLOIT LINE] donateToReserves() is the only mechanism that spikes
        //   reserves discontinuously. Combined with borrow growth = attack fingerprint.
        // [TRAP LINE B] fires during leverage+donation phase, before liquidation
        if (base.totalReserves > 0 && curr.totalReserves > base.totalReserves) {
            uint256 reserveGrowthBps =
                (curr.totalReserves - base.totalReserves) * BPS / base.totalReserves;

            bool reserveSpike = reserveGrowthBps >= RESERVE_SPIKE_BPS;
            bool borrowsGrew  = curr.totalBorrows > base.totalBorrows;

            if (reserveSpike && borrowsGrew) {
                return (true, abi.encode(
                    "TRIGGERED: DonationAttackVelocityAnomaly()",
                    reserveGrowthBps,
                    curr.totalBorrows - base.totalBorrows,
                    curr.blockNumber
                ));
            }
        }

        return (false, bytes(""));
    }
}
