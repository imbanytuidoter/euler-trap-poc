// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "./helpers/TrapHarness.sol";

contract EulerTrapFuzz is TrapHarness {

    address public alice = makeAddr("alice");
    address public atk1  = makeAddr("atk1");
    address public atk2  = makeAddr("atk2");

    uint256 constant ONE_M = 1_000_000 * 1e18;
    uint256 constant CF    = 7500;
    uint256 constant BPS   = 10_000;

    function setUp() public {
        _deployHarness();
        vm.roll(16_818_050);

        vm.prank(alice);
        euler.deposit(50 * ONE_M);
        vm.prank(alice);
        euler.borrow(30 * ONE_M);
    }

    function _fiveSampleWindow(bytes memory baseline) internal returns (bytes[] memory) {
        _flushLogsToTrap();
        bytes[] memory w = new bytes[](5);
        w[0] = trap.collect();
        w[1] = _cleanBaselineEncoded();
        w[2] = _cleanBaselineEncoded();
        w[3] = _cleanBaselineEncoded();
        w[4] = baseline;
        return w;
    }

    // Fuzz 1: no false positives under arbitrary normal deposits/borrows.
    function testFuzz_NoFalsePositive_NormalBorrowAndDeposit(
        uint256 depositAmt,
        uint256 borrowFrac
    ) public {
        depositAmt = bound(depositAmt, 1e18, 1_000 * ONE_M);
        borrowFrac = bound(borrowFrac, 0, 7_400); // strictly below CF

        bytes memory baseline = _cleanBaselineEncoded();

        vm.startPrank(atk1);
        euler.deposit(depositAmt);
        uint256 borrowAmt = depositAmt * borrowFrac / BPS;
        if (borrowAmt > 0) euler.borrow(borrowAmt);
        vm.stopPrank();

        (bool triggered, ) = trap.shouldRespond(_fiveSampleWindow(baseline));
        assertFalse(triggered, "must not trigger on normal activity");
    }

    // Fuzz 2: trigger fires for any meaningful bad debt amount.
    function testFuzz_TriggerOnBadDebt(
        uint256 depositAmt,
        uint256 donateAmt
    ) public {
        depositAmt = bound(depositAmt, 10 * ONE_M, 500 * ONE_M);
        uint256 borrowAmt = depositAmt * CF / BPS;
        uint256 minDonate = depositAmt / 3 + 1;
        donateAmt = bound(donateAmt, minDonate, depositAmt - 1);

        bytes memory baseline = _cleanBaselineEncoded();

        vm.startPrank(atk1);
        euler.deposit(depositAmt);
        euler.borrow(borrowAmt);
        euler.donateToReserves(donateAmt);
        vm.stopPrank();

        (uint256 col, uint256 liab) = euler.getAccountLiquidity(atk1);
        if (liab <= col) return; // donation wasn't enough, skip

        uint256 repayAmt = borrowAmt / 4;
        vm.prank(atk2);
        euler.liquidate(atk1, repayAmt);

        address[] memory accts = new address[](1);
        accts[0] = atk1;
        uint256 badDebt = euler.getTotalBadDebt(accts);
        vm.assume(badDebt > 0);

        (bool triggered, bytes memory payload) = trap.shouldRespond(_fiveSampleWindow(baseline));
        assertTrue(triggered, "must trigger when bad debt exists");

        (uint8 triggerType, , , ) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
    }

    // Fuzz 3: reserve spike threshold boundary.
    // donationBps = growth of reserves relative to baseline (e.g. 5000 = +50%).
    function testFuzz_ReserveSpike_ThresholdBoundary(uint256 donationBps) public {
        donationBps = bound(donationBps, 1, 20_000);

        uint256 existingReserves = 10 * ONE_M;
        uint256 donationAmount = existingReserves * (BPS + donationBps) / BPS;

        bytes memory baseline = _baselineWithReserves(existingReserves, 30 * ONE_M);

        vm.startPrank(atk1);
        euler.deposit(200 * ONE_M);
        euler.borrow(100 * ONE_M);
        euler.donateToReserves(donationAmount);
        vm.stopPrank();

        (bool triggered, ) = trap.shouldRespond(_fiveSampleWindow(baseline));

        if (donationBps >= 5_000) {
            assertTrue(triggered, "must trigger at >= 50% reserve spike with borrow growth");
        } else {
            assertFalse(triggered, "must not trigger below 50% threshold");
        }
    }

    // Fuzz 4: shouldRespond handles any window size without reverting.
    // Below MIN_SAMPLE_SIZE (5) → never triggers (window-size guard).
    function testFuzz_WindowSize_Robustness(uint8 windowSize) public {
        windowSize = uint8(bound(windowSize, 0, 20));

        _flushLogsToTrap();
        bytes[] memory w = new bytes[](windowSize);
        for (uint256 i; i < windowSize; i++) {
            w[i] = trap.collect();
        }

        (bool triggered, ) = trap.shouldRespond(w);

        if (windowSize < trap.MIN_SAMPLE_SIZE()) {
            assertFalse(triggered, "< MIN_SAMPLE_SIZE must not trigger");
        } else {
            // identical clean snapshots (no growth, no bad debt) — must not trigger
            assertFalse(triggered, "identical clean windows must not trigger");
        }
    }

    // Edge case: zero baseline reserves — relative velocity disabled, but
    // ABSOLUTE_RESERVE_SPIKE catches the equivalent in absolute terms.
    function test_EdgeCase_ZeroBaselineReserves_NoDivByZero() public {
        bytes memory baseline = _cleanBaselineEncoded();

        // Smaller donation than ABSOLUTE_RESERVE_SPIKE → no trigger
        vm.startPrank(atk1);
        euler.deposit(100 * ONE_M);
        euler.borrow(50 * ONE_M);
        euler.donateToReserves(10 * ONE_M); // 10M < 1M e18 threshold? need check
        vm.stopPrank();

        (bool triggered, ) = trap.shouldRespond(_fiveSampleWindow(baseline));
        // 10M units == 10_000_000e18 which IS >= ABSOLUTE_RESERVE_SPIKE (1M e18)
        // So this DOES trigger AbsoluteReserveSpike. That's correct.
        assertTrue(triggered, "10M reserve donation from zero baseline must trigger absolute spike");
    }
}
