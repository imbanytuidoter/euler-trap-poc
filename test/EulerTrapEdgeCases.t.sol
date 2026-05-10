// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "./helpers/TrapHarness.sol";

contract EulerTrapEdgeCases is TrapHarness {
    address public alice = makeAddr("alice");
    address public atk1 = makeAddr("atk1");
    address public atk2 = makeAddr("atk2");
    address public atk3 = makeAddr("atk3");

    uint256 constant ONE_M = 1_000_000 * 1e18;
    uint256 constant CF = 7500;
    uint256 constant BPS = 10_000;

    function setUp() public {
        _deployHarness();
        vm.roll(16_818_050);
        vm.prank(alice);
        euler.deposit(50 * ONE_M);
        vm.prank(alice);
        euler.borrow(30 * ONE_M);
    }

    // -------- discovery --------

    // Event-based discovery picks up any address that touches the market via
    // the subscribed signatures, no constructor whitelist required.
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

        (uint8 triggerType, uint256 badDebt,,) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
        assertGt(badDebt, 0);
    }

    // Discovery is bounded by MAX_ACCOUNTS = 32. If 40 spammers each emit a
    // Deposit, Deposit alone would fill the cap. Prioritization runs Donate
    // and Liquidate-violator first, so the actual offender is still discovered.
    function test_DiscoveryPriority_DonationAccountSurvivesDepositSpam() public {
        for (uint256 i = 0; i < 40; i++) {
            address spammer = address(uint160(uint256(keccak256(abi.encode("spam", i)))));
            vm.prank(spammer);
            euler.deposit(1e18);
        }

        address freshAttacker = makeAddr("priority_attacker");

        vm.startPrank(freshAttacker);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();

        vm.prank(atk2);
        euler.liquidate(freshAttacker, 375 * 1e5 * 1e18);

        _flushLogsToTrap();
        bytes[] memory window = _windowWithCurrent(trap.collect());

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "priority discovery must catch donation account despite deposit spam");

        (uint8 triggerType, uint256 badDebt,,) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
        assertGt(badDebt, 0);
    }

    // -------- read failure (alert-only, never auto-pause) --------

    function test_ReadFailure_TotalReserves_AlertsOnly() public {
        _flushLogsToTrap();
        vm.mockCallRevert(eulerAddr, abi.encodeWithSelector(IEulerMarket.totalReserves.selector), "node down");

        bytes memory current = trap.collect();
        EulerFinanceTrap.CollectOutput memory out = abi.decode(current, (EulerFinanceTrap.CollectOutput));
        assertFalse(out.reservesReadOk, "reservesReadOk must be false");
        assertTrue(out.borrowsReadOk, "borrowsReadOk should still be true");

        bytes[] memory window = _windowWithCurrent(current);

        (bool shouldRespondTrigger,) = trap.shouldRespond(window);
        assertFalse(shouldRespondTrigger, "read failure must not auto-trigger response");

        (bool shouldAlertTrigger, bytes memory alertPayload) = trap.shouldAlert(window);
        assertTrue(shouldAlertTrigger, "read failure must alert");

        (uint8 triggerType,,,) = abi.decode(alertPayload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.ReadFailureAlertOnly));
    }

    function test_ReadFailure_TotalBorrows_AlertsOnly() public {
        _flushLogsToTrap();
        vm.mockCallRevert(eulerAddr, abi.encodeWithSelector(IEulerMarket.totalBorrows.selector), "node down");

        bytes memory current = trap.collect();
        bytes[] memory window = _windowWithCurrent(current);

        (bool shouldRespondTrigger,) = trap.shouldRespond(window);
        assertFalse(shouldRespondTrigger);

        (bool shouldAlertTrigger, bytes memory alertPayload) = trap.shouldAlert(window);
        assertTrue(shouldAlertTrigger);

        (uint8 triggerType,,,) = abi.decode(alertPayload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.ReadFailureAlertOnly));
    }

    function test_ReadFailure_AccountLiquidity_AlertsOnly() public {
        // need an account discovered via events first
        vm.prank(atk1);
        euler.deposit(10 * ONE_M);
        _flushLogsToTrap();

        vm.mockCallRevert(
            eulerAddr, abi.encodeWithSelector(IEulerMarket.getAccountLiquidity.selector, atk1), "rpc error"
        );

        bytes memory current = trap.collect();
        EulerFinanceTrap.CollectOutput memory out = abi.decode(current, (EulerFinanceTrap.CollectOutput));
        assertFalse(out.accountReadsOk, "accountReadsOk must be false");

        bytes[] memory window = _windowWithCurrent(current);

        (bool shouldRespondTrigger,) = trap.shouldRespond(window);
        assertFalse(shouldRespondTrigger);

        (bool shouldAlertTrigger, bytes memory alertPayload) = trap.shouldAlert(window);
        assertTrue(shouldAlertTrigger);

        (uint8 triggerType,,,) = abi.decode(alertPayload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.ReadFailureAlertOnly));
    }

    // -------- malformed input --------

    // Garbage bytes in the sample window must not crash shouldRespond.
    function test_MalformedCollectSample_DoesNotRevertShouldRespond() public view {
        bytes[] memory window = new bytes[](5);
        window[0] = hex"1234";
        window[1] = _cleanBaselineEncoded();
        window[2] = _cleanBaselineEncoded();
        window[3] = _cleanBaselineEncoded();
        window[4] = _cleanBaselineEncoded();

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);

        assertFalse(triggered);
        assertEq(payload.length, 0);
    }

    // -------- velocity / absolute spike --------

    function test_ZeroBaseline_AbsoluteReserveSpike_Triggers() public {
        vm.startPrank(atk1);
        euler.deposit(500 * ONE_M);
        euler.borrow(100 * ONE_M);
        euler.donateToReserves(2 * ONE_M); // 2M units >= 1M threshold
        vm.stopPrank();
        _flushLogsToTrap();

        bytes[] memory window = _windowWithCurrent(trap.collect());

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "absolute spike must fire when base reserves are zero");

        (uint8 triggerType,,,) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.AbsoluteReserveSpike));
    }

    function test_ZeroBaseline_BelowAbsoluteThreshold_NoTrigger() public {
        vm.startPrank(atk1);
        euler.deposit(10 * ONE_M);
        euler.borrow(5 * ONE_M);
        euler.donateToReserves(500_000 * 1e18);
        vm.stopPrank();
        _flushLogsToTrap();

        bytes[] memory window = _windowWithCurrent(trap.collect());

        (bool triggered,) = trap.shouldRespond(window);
        assertFalse(triggered, "small donation under absolute threshold must not trigger");
    }

    // -------- window robustness --------

    function test_LongerWindow_DoesNotDistortDetection() public {
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(atk1, 375 * 1e5 * 1e18);
        _flushLogsToTrap();

        bytes memory current = trap.collect();

        bytes[] memory window = new bytes[](10);
        window[0] = current;
        for (uint256 i = 1; i < 10; i++) {
            window[i] = _cleanBaselineEncoded();
        }

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "BadDebt must fire regardless of window length");

        (uint8 triggerType,,,) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
    }

    // -------- attack distribution --------

    function test_AttackSplit_AcrossMultipleAddresses() public {
        address[3] memory attackers = [atk1, atk2, atk3];
        for (uint256 i = 0; i < attackers.length; i++) {
            vm.startPrank(attackers[i]);
            euler.mint(50 * ONE_M, 50 * ONE_M * CF / BPS);
            euler.donateToReserves(33 * ONE_M);
            vm.stopPrank();

            address liqr = makeAddr(string(abi.encodePacked("liqr", i)));
            vm.prank(liqr);
            euler.liquidate(attackers[i], 12_500_000 * 1e18);
        }
        _flushLogsToTrap();

        bytes[] memory window = _windowWithCurrent(trap.collect());
        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "split-address attack must trigger BadDebt");

        (uint8 triggerType, uint256 badDebt, uint256 unhealthyCount,) =
            abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
        assertGt(badDebt, 0);
        assertGe(unhealthyCount, 3, "at least 3 unhealthy attacker accounts discovered");
    }

    function test_AttackSplit_AcrossMultipleSmallerDonations() public {
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
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

        (uint8 triggerType,,,) = abi.decode(payload, (uint8, uint256, uint256, uint256));
        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt));
    }

    // -------- no false positives --------

    function test_LegitimateDonation_WithoutBorrowGrowth_NoFalsePositive() public {
        bytes memory baseline = _baselineWithReserves(2 * ONE_M, 30 * ONE_M);

        vm.startPrank(alice);
        euler.deposit(100 * ONE_M);
        euler.donateToReserves(50 * ONE_M);
        vm.stopPrank();
        _flushLogsToTrap();

        bytes memory current = trap.collect();
        bytes[] memory window = _windowWithCurrentAndBase(current, baseline);

        (bool triggered,) = trap.shouldRespond(window);
        assertFalse(triggered, "donation without borrow growth must not trigger");
    }

    function test_BorrowGrowth_WithoutReserveSpike_NoFalsePositive() public {
        bytes memory baseline = _baselineWithReserves(10 * ONE_M, 30 * ONE_M);

        vm.startPrank(atk1);
        euler.deposit(200 * ONE_M);
        euler.borrow(100 * ONE_M);
        vm.stopPrank();
        _flushLogsToTrap();

        bytes memory current = trap.collect();
        bytes[] memory window = _windowWithCurrentAndBase(current, baseline);

        (bool triggered,) = trap.shouldRespond(window);
        assertFalse(triggered, "borrow growth without reserve spike must not trigger");
    }
}
