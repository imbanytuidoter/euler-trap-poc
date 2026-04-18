// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/EulerFinanceTrap.sol";
import "../src/mocks/MockEulerMarket.sol";

contract EulerTrapFuzz is Test {

    MockEulerMarket  public euler;
    EulerFinanceTrap public trap;

    address public alice = makeAddr("alice");
    address public atk1  = makeAddr("atk1");
    address public atk2  = makeAddr("atk2");

    uint256 constant ONE_M = 1_000_000 * 1e18;
    uint256 constant CF    = 7500;
    uint256 constant BPS   = 10_000;

    address[] public tracked;

    function setUp() public {
        euler = new MockEulerMarket();
        tracked = new address[](3);
        tracked[0] = alice; tracked[1] = atk1; tracked[2] = atk2;
        trap = new EulerFinanceTrap(address(euler), tracked);

        vm.roll(16_818_050);

        vm.prank(alice);
        euler.deposit(50 * ONE_M);
        vm.prank(alice);
        euler.borrow(30 * ONE_M);
    }

    function _twoSampleWindow(bytes memory olderSnapshot)
        internal view
        returns (bytes[] memory)
    {
        bytes[] memory w = new bytes[](2);
        w[0] = trap.collect();
        w[1] = olderSnapshot;
        return w;
    }

    function _cleanBaseline() internal view returns (bytes memory) {
        return abi.encode(
            EulerFinanceTrap.CollectOutput({
                totalBadDebt  : 0,
                totalReserves : 0,
                totalBorrows  : 30 * ONE_M,
                totalDeposits : 50 * ONE_M,
                blockNumber   : block.number - 5
            })
        );
    }

    // Fuzz 1: no false positives under arbitrary normal deposits/borrows
    function testFuzz_NoFalsePositive_NormalBorrowAndDeposit(
        uint256 depositAmt,
        uint256 borrowFrac
    ) public {
        depositAmt = bound(depositAmt, 1e18, 1_000 * ONE_M);
        borrowFrac = bound(borrowFrac, 0, 7_400); // strictly below CF

        bytes memory baseline = _cleanBaseline();

        vm.startPrank(atk1);
        euler.deposit(depositAmt);
        uint256 borrowAmt = depositAmt * borrowFrac / BPS;
        if (borrowAmt > 0) euler.borrow(borrowAmt);
        vm.stopPrank();

        (bool triggered, ) = trap.shouldRespond(_twoSampleWindow(baseline));
        assertFalse(triggered, "must not trigger on normal activity");
    }

    // Fuzz 2: trigger fires for any meaningful bad debt amount
    function testFuzz_TriggerOnBadDebt(
        uint256 depositAmt,
        uint256 donateAmt
    ) public {
        depositAmt = bound(depositAmt, 10 * ONE_M, 500 * ONE_M);
        uint256 borrowAmt = depositAmt * CF / BPS;
        uint256 minDonate = depositAmt / 3 + 1;
        donateAmt = bound(donateAmt, minDonate, depositAmt - 1);

        bytes memory baseline = _cleanBaseline();

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

        (bool triggered, ) = trap.shouldRespond(_twoSampleWindow(baseline));
        assertTrue(triggered, "must trigger when bad debt exists");
    }

    // Fuzz 3: reserve spike threshold boundary
    // donationBps = growth of reserves relative to baseline (e.g. 5000 = +50%)
    // donationAmount chosen so curr.totalReserves = existingReserves * (1 + donationBps/BPS)
    function testFuzz_ReserveSpike_ThresholdBoundary(uint256 donationBps) public {
        donationBps = bound(donationBps, 1, 20_000);

        uint256 existingReserves = 10 * ONE_M;
        // Mock starts at 0 reserves; after donation curr = donationAmount.
        // We want growth = (curr - base) / base = donationBps/BPS, so:
        // curr = existingReserves * (BPS + donationBps) / BPS
        uint256 donationAmount = existingReserves * (BPS + donationBps) / BPS;

        bytes memory baseline = abi.encode(
            EulerFinanceTrap.CollectOutput({
                totalBadDebt  : 0,
                totalReserves : existingReserves,
                totalBorrows  : 30 * ONE_M,
                totalDeposits : 50 * ONE_M,
                blockNumber   : block.number - 5
            })
        );

        vm.startPrank(atk1);
        euler.deposit(200 * ONE_M);
        euler.borrow(100 * ONE_M);
        euler.donateToReserves(donationAmount);
        vm.stopPrank();

        (bool triggered, ) = trap.shouldRespond(_twoSampleWindow(baseline));

        if (donationBps >= 5_000) {
            assertTrue(triggered, "must trigger at >= 50% reserve spike with borrow growth");
        } else {
            assertFalse(triggered, "must not trigger below 50% threshold");
        }
    }

    // Fuzz 4: shouldRespond handles any window size without reverting
    function testFuzz_WindowSize_Robustness(uint8 windowSize) public {
        windowSize = uint8(bound(windowSize, 0, 20));

        bytes[] memory w = new bytes[](windowSize);
        for (uint256 i; i < windowSize; i++) {
            w[i] = trap.collect();
        }

        (bool triggered, ) = trap.shouldRespond(w);

        if (windowSize < 2) {
            assertFalse(triggered, "< 2 samples must not trigger");
        } else {
            assertFalse(triggered, "identical clean windows must not trigger");
        }
    }

    // Edge case: zero baseline reserves — no div-by-zero
    function test_EdgeCase_ZeroBaselineReserves_NoDivByZero() public {
        bytes memory baseline = abi.encode(
            EulerFinanceTrap.CollectOutput({
                totalBadDebt  : 0,
                totalReserves : 0,
                totalBorrows  : 30 * ONE_M,
                totalDeposits : 50 * ONE_M,
                blockNumber   : block.number - 1
            })
        );

        vm.startPrank(atk1);
        euler.deposit(100 * ONE_M);
        euler.borrow(50 * ONE_M);
        euler.donateToReserves(10 * ONE_M);
        vm.stopPrank();

        // Must not revert. No bad debt (no liquidation), inv2 guard skips div-by-zero.
        (bool triggered, ) = trap.shouldRespond(_twoSampleWindow(baseline));
        assertFalse(triggered, "no bad debt, no velocity trigger");
    }
}
