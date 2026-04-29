// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "./helpers/TrapHarness.sol";

// Edge cases enumerated in the reviewer's PoC review:
//   - Unknown attacker (event discovery works for any caller of the market)
//   - Read failures (totalReserves, totalBorrows, getAccountLiquidity)
//   - Zero-baseline absolute spike trigger
//   - Window size > MIN_SAMPLE_SIZE doesn't distort thresholds
//   - Attack split across multiple addresses
//   - Attack split across multiple smaller donations
//   - Legitimate large donation without borrow growth (no false positive)
//   - Borrow growth without reserves growth (no false positive)

contract EulerTrapEdgeCases is TrapHarness {

    address public alice = makeAddr("alice");
    address public atk1  = makeAddr("atk1");
    address public atk2  = makeAddr("atk2");
    address public atk3  = makeAddr("atk3");

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

    // The original PoC's biggest gap: an attacker not in the constructor's
    // trackedAccounts list was invisible. With event-based discovery, ANY
    // address that touches the market via Deposit/Borrow/Mint/Donate/Liquidate
    // gets picked up automatically — there is no whitelist to be outside of.
    function test_UnknownAttacker_DiscoveredViaEvents() public {
        address freshAttacker = makeAddr("never_seen_before");

        vm.startPrank(freshAttacker);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(freshAttacker, 375 * 1e5 * 1e18);

        _flushLogsToTrap();
        bytes[] memory window = _windowWithCurrent(trap.collect());

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "unknown attacker must still trigger BadDebt invariant");

        (uint8 triggerType, uint256 badDebt, , ) =
            abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
        assertGt(badDebt, 0);
    }

    // A read failure is itself a signal — silent zero would be a false negative.
    function test_ReadFailure_TotalReserves_FiresReadFailureTrigger() public {
        _flushLogsToTrap();
        vm.mockCallRevert(
            eulerAddr,
            abi.encodeWithSelector(IEulerMarket.totalReserves.selector),
            "node down"
        );

        bytes memory current = trap.collect();
        EulerFinanceTrap.CollectOutput memory out =
            abi.decode(current, (EulerFinanceTrap.CollectOutput));
        assertFalse(out.reservesReadOk, "reservesReadOk must be false");
        assertTrue(out.borrowsReadOk, "borrowsReadOk should still be true");

        (bool triggered, bytes memory payload) =
            trap.shouldRespond(_windowWithCurrent(current));
        assertTrue(triggered, "ReadFailure must trigger response");

        (uint8 triggerType, , , ) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.ReadFailure));
    }

    function test_ReadFailure_TotalBorrows_FiresReadFailureTrigger() public {
        _flushLogsToTrap();
        vm.mockCallRevert(
            eulerAddr,
            abi.encodeWithSelector(IEulerMarket.totalBorrows.selector),
            "node down"
        );

        bytes memory current = trap.collect();
        (bool triggered, bytes memory payload) =
            trap.shouldRespond(_windowWithCurrent(current));
        assertTrue(triggered);
        (uint8 triggerType, , , ) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.ReadFailure));
    }

    function test_ReadFailure_AccountLiquidity_FiresReadFailureTrigger() public {
        // Need an account discovered via events, then make its liquidity read revert
        vm.prank(atk1);
        euler.deposit(10 * ONE_M);
        _flushLogsToTrap();

        vm.mockCallRevert(
            eulerAddr,
            abi.encodeWithSelector(IEulerMarket.getAccountLiquidity.selector, atk1),
            "rpc error"
        );

        bytes memory current = trap.collect();
        EulerFinanceTrap.CollectOutput memory out =
            abi.decode(current, (EulerFinanceTrap.CollectOutput));
        assertFalse(out.accountReadsOk, "accountReadsOk must be false");

        (bool triggered, bytes memory payload) =
            trap.shouldRespond(_windowWithCurrent(current));
        assertTrue(triggered);
        (uint8 triggerType, , , ) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.ReadFailure));
    }

    // Zero baseline reserves: relative velocity guard skips, absolute threshold catches it.
    function test_ZeroBaseline_AbsoluteReserveSpike_Triggers() public {
        // Donation big enough to cross ABSOLUTE_RESERVE_SPIKE (1M e18 = 1M units)
        vm.startPrank(atk1);
        euler.deposit(500 * ONE_M);
        euler.borrow(100 * ONE_M);
        euler.donateToReserves(2 * ONE_M); // 2M units >= 1M threshold
        vm.stopPrank();
        _flushLogsToTrap();

        bytes[] memory window = _windowWithCurrent(trap.collect());

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "absolute spike must fire when base reserves are zero");

        (uint8 triggerType, , , ) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.AbsoluteReserveSpike));
    }

    // Below absolute threshold + zero baseline + no bad debt → no false positive.
    function test_ZeroBaseline_BelowAbsoluteThreshold_NoTrigger() public {
        vm.startPrank(atk1);
        euler.deposit(10 * ONE_M);
        euler.borrow(5 * ONE_M);
        // 0.5M units < 1M absolute threshold
        euler.donateToReserves(500_000 * 1e18);
        vm.stopPrank();
        _flushLogsToTrap();

        bytes[] memory window = _windowWithCurrent(trap.collect());

        (bool triggered, ) = trap.shouldRespond(window);
        assertFalse(triggered, "small donation under absolute threshold must not trigger");
    }

    // Reviewer point: window size > MIN_SAMPLE_SIZE should not distort detection.
    function test_LongerWindow_DoesNotDistortDetection() public {
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(atk1, 375 * 1e5 * 1e18);
        _flushLogsToTrap();

        bytes memory current = trap.collect();

        // 10-block window — should still fire (BadDebt is invariant)
        bytes[] memory window = new bytes[](10);
        window[0] = current;
        for (uint256 i = 1; i < 10; i++) window[i] = _cleanBaselineEncoded();

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "BadDebt must fire regardless of window length");

        (uint8 triggerType, , , ) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
    }

    // Attack split across multiple addresses — each one performs the donation
    // sequence with separately-funded positions. Aggregated bad debt across
    // multiple discovered accounts must still fire.
    function test_AttackSplit_AcrossMultipleAddresses() public {
        address[3] memory attackers = [atk1, atk2, atk3];
        for (uint256 i = 0; i < attackers.length; i++) {
            vm.startPrank(attackers[i]);
            euler.mint(50 * ONE_M, 50 * ONE_M * CF / BPS);
            euler.donateToReserves(33 * ONE_M);
            vm.stopPrank();

            // Use a fresh helper liquidator each time so we have a separate EOA
            address liqr = makeAddr(string(abi.encodePacked("liqr", i)));
            vm.prank(liqr);
            euler.liquidate(attackers[i], 12_500_000 * 1e18);
        }
        _flushLogsToTrap();

        bytes[] memory window = _windowWithCurrent(trap.collect());
        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "split-address attack must trigger BadDebt");

        (uint8 triggerType, uint256 badDebt, uint256 unhealthyCount, ) =
            abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
        assertGt(badDebt, 0);
        assertGe(unhealthyCount, 3, "at least 3 unhealthy attacker accounts discovered");
    }

    // Multiple smaller donations summing above the threshold must still fire.
    function test_AttackSplit_AcrossMultipleSmallerDonations() public {
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        // 5 × 22M donations = 110M total. Each below half of collateral but
        // collectively large enough to push the position underwater.
        for (uint256 i = 0; i < 5; i++) {
            euler.donateToReserves(22 * ONE_M);
        }
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(atk1, 50 * ONE_M);
        _flushLogsToTrap();

        bytes[] memory window = _windowWithCurrent(trap.collect());
        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "split-donation attack must trigger");

        (uint8 triggerType, , , ) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
    }

    // Legitimate large donation with no borrow growth must NOT trigger.
    // Velocity invariant requires BOTH reserve growth AND borrow growth.
    function test_LegitimateDonation_WithoutBorrowGrowth_NoFalsePositive() public {
        // baseline already has 30M borrows from setUp's alice
        bytes memory baseline = _baselineWithReserves(2 * ONE_M, 30 * ONE_M);

        // Legitimate top-up: someone donates to reserves but borrows don't grow.
        // Use a wealthy depositor — must keep healthy positions throughout.
        vm.startPrank(alice);
        euler.deposit(100 * ONE_M);
        euler.donateToReserves(50 * ONE_M);
        vm.stopPrank();
        _flushLogsToTrap();

        bytes memory current = trap.collect();
        bytes[] memory window = _windowWithCurrentAndBase(current, baseline);

        (bool triggered, ) = trap.shouldRespond(window);
        assertFalse(triggered, "donation without borrow growth must not trigger");
    }

    // Pure borrow growth (no reserve donation) must NOT trigger velocity.
    function test_BorrowGrowth_WithoutReserveSpike_NoFalsePositive() public {
        bytes memory baseline = _baselineWithReserves(10 * ONE_M, 30 * ONE_M);

        vm.startPrank(atk1);
        euler.deposit(200 * ONE_M);
        euler.borrow(100 * ONE_M);
        vm.stopPrank();
        _flushLogsToTrap();

        bytes memory current = trap.collect();
        bytes[] memory window = _windowWithCurrentAndBase(current, baseline);

        (bool triggered, ) = trap.shouldRespond(window);
        assertFalse(triggered, "borrow growth without reserve spike must not trigger");
    }
}
