// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "./helpers/TrapHarness.sol";
import "../src/response/EulerPauseResponse.sol";

// Verifies that the Trap detects each attack phase and that the response
// contract correctly halts the market when triggered. Accounts are
// discovered via event logs (Drosera's getEventLogs path) — no constructor
// account list, no shared trackedAccounts state.

contract EulerTrapDetection is TrapHarness {

    EulerPauseResponse public response;

    address public alice       = makeAddr("alice");
    address public atk1        = makeAddr("atk1");
    address public atk2        = makeAddr("atk2");
    address public trapManager = makeAddr("trapManager");

    uint256 constant ONE_M = 1_000_000 * 1e18;
    uint256 constant CF    = 7500;
    uint256 constant BPS   = 10_000;

    function setUp() public {
        _deployHarness();
        response = new EulerPauseResponse(eulerAddr, trapManager);

        vm.roll(16_818_050);

        vm.prank(alice);
        euler.deposit(30 * ONE_M);
        vm.prank(alice);
        euler.borrow(20 * ONE_M);
    }

    // [1] No false positives during normal operation across a 5-block window
    function test_NoFalsePositive_NormalOperation() public {
        bytes[] memory window = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            _flushLogsToTrap();
            window[i] = trap.collect();
            vm.roll(block.number + 1);
        }
        (bool triggered, ) = trap.shouldRespond(_newestFirst(window));
        assertFalse(triggered, "MUST NOT trigger on normal operation");
        console.log("[OK] No false positive across 5 normal blocks");
    }

    // [2] Invariant 1 fires when bad debt appears on a discovered account
    function test_Invariant1_BadDebt_TriggersShouldRespond() public {
        bytes[] memory window = new bytes[](5);

        for (uint256 i = 0; i < 3; i++) {
            _flushLogsToTrap();
            window[i] = trap.collect();
            vm.roll(block.number + 1);
        }

        // Exploit: build position, donate, liquidate → bad debt
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(atk1, 375 * 1e5 * 1e18);

        _flushLogsToTrap();
        window[3] = trap.collect();
        vm.roll(block.number + 1);
        _flushLogsToTrap();
        window[4] = trap.collect();

        (bool triggered, bytes memory payload) = trap.shouldRespond(_newestFirst(window));
        assertTrue(triggered, "shouldRespond() MUST return true when bad debt exists");

        (uint8 triggerType, uint256 badDebt, uint256 unhealthyCount, uint256 atBlock) =
            abi.decode(payload, (uint8, uint256, uint256, uint256));

        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.BadDebt), "must be BadDebt trigger");
        assertGt(badDebt, 0, "non-zero bad debt amount");
        assertGt(unhealthyCount, 0, "unhealthy account count > 0");

        console.log("[TRIGGERED] BadDebt invariant");
        console.log("  bad debt (sampled):", badDebt);
        console.log("  unhealthy accounts:", unhealthyCount);
        console.log("  at block:", atBlock);
    }

    // [3] Invariant 2: ReserveVelocity fires before bad debt exists.
    // Attacker overcollateralizes (HF stays > 1) so getAccountLiquidity reports
    // healthy. Reserves still spike from 5M baseline to 45M (+800%) — early warning.
    function test_Invariant2_ReserveVelocity_TriggersShouldRespond() public {
        // Build attacker activity so the discovery path captures atk1.
        // 500M deposit + 100M borrow → HF = 3.45 (still solvent after donation).
        vm.startPrank(atk1);
        euler.deposit(500 * ONE_M);
        euler.borrow(100 * ONE_M);
        euler.donateToReserves(40 * ONE_M);
        vm.stopPrank();

        _flushLogsToTrap();
        bytes memory current = trap.collect();

        // Decode current to assert no bad debt was triggered (proving Invariant 2 fired alone)
        EulerFinanceTrap.CollectOutput memory currOut =
            abi.decode(current, (EulerFinanceTrap.CollectOutput));
        assertEq(currOut.sampledBadDebt, 0, "position must remain solvent");
        assertGt(currOut.totalReserves, 5 * ONE_M, "reserves must have spiked");

        // base.totalReserves = 5M, curr.totalReserves = 40M → growth = 700% → trigger
        bytes[] memory window = _windowWithCurrentAndBase(
            current,
            _baselineWithReserves(5 * ONE_M, 30 * ONE_M)
        );

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "shouldRespond() MUST trigger on velocity anomaly");

        (uint8 triggerType, uint256 growthBps, uint256 borrowIncrease, ) =
            abi.decode(payload, (uint8, uint256, uint256, uint256));

        assertEq(triggerType, uint8(EulerFinanceTrap.TriggerType.ReserveVelocity), "must be ReserveVelocity");
        assertGe(growthBps, trap.RESERVE_SPIKE_BPS(), "growth >= 50%");
        assertGt(borrowIncrease, 0, "borrows must have grown");

        console.log("[TRIGGERED - EARLY WARNING] ReserveVelocity");
        console.log("  reserve growth BPS:", growthBps);
        console.log("  borrow increase (wei):", borrowIncrease);
    }

    // [4] Full end-to-end mitigation
    function test_FullMitigation_AttackerCannotExit() public {
        // Run the exploit and discover atk1+atk2 via events
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(atk1, 375 * 1e5 * 1e18);

        _flushLogsToTrap();
        bytes[] memory window = _windowWithCurrent(trap.collect());

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "trap must fire");

        // Drosera operator calls respond() with the trap's payload
        vm.prank(trapManager);
        response.respond(payload);
        assertTrue(euler.paused(), "market must be paused");

        // Real exit paths must all be blocked
        vm.expectRevert("MockEuler: market paused");
        vm.prank(atk2);
        euler.withdraw(1);

        vm.expectRevert("MockEuler: market paused");
        vm.prank(atk2);
        euler.redeem(1);

        vm.expectRevert("MockEuler: market paused");
        vm.prank(atk2);
        euler.transferEToken(makeAddr("cex"), 1);

        (uint256 atk2Collateral, ) = euler.getAccountLiquidity(atk2);
        assertGt(atk2Collateral, 0, "stolen collateral is locked");

        console.log("=== MITIGATION COMPLETE ===");
        console.log("Market paused:", euler.paused());
        console.log("Locked attacker collateral:", atk2Collateral);
        console.log("Successful exit paths: 0 / 3");
    }

    // [5] Window shorter than MIN_SAMPLE_SIZE → no trigger (threshold sanity)
    function test_InsufficientWindow_NoTrigger() public {
        // Force bad debt to actually exist
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(atk1, 375 * 1e5 * 1e18);
        _flushLogsToTrap();

        bytes memory current = trap.collect();

        // 4 samples — one below MIN_SAMPLE_SIZE = 5
        bytes[] memory four = new bytes[](4);
        four[0] = current;
        four[1] = _cleanBaselineEncoded();
        four[2] = _cleanBaselineEncoded();
        four[3] = _cleanBaselineEncoded();
        (bool triggered, ) = trap.shouldRespond(four);
        assertFalse(triggered, "must not trigger with < MIN_SAMPLE_SIZE samples");

        // 1 sample
        bytes[] memory one = new bytes[](1);
        one[0] = current;
        (triggered, ) = trap.shouldRespond(one);
        assertFalse(triggered);

        // 0 samples
        bytes[] memory zero = new bytes[](0);
        (triggered, ) = trap.shouldRespond(zero);
        assertFalse(triggered);
    }

    // [6] Only trapManager can call respond()
    function test_ResponseAuthorization_OnlyTrapManager() public {
        vm.expectRevert(
            abi.encodeWithSelector(EulerPauseResponse.OnlyTrapManager.selector, address(this))
        );
        response.respond(_validBadDebtPayload());
    }

    // [7] Cooldown / double-fire: respond() reverts if market already paused
    function test_DoubleResponse_RevertsAlreadyPaused() public {
        vm.prank(trapManager);
        response.respond(_validBadDebtPayload());
        assertTrue(euler.paused());

        vm.expectRevert(EulerPauseResponse.AlreadyPaused.selector);
        vm.prank(trapManager);
        response.respond(_validBadDebtPayload());
    }

    // [8] Malformed payload (wrong size) is rejected, not silently mis-decoded
    function test_MalformedPayload_Reverts() public {
        vm.expectRevert(EulerPauseResponse.InvalidPayload.selector);
        vm.prank(trapManager);
        response.respond(hex"00");

        // Trigger type 0 (None) is also rejected
        bytes memory badPayload = abi.encode(uint8(0), uint256(0), uint256(0), uint256(0));
        vm.expectRevert(abi.encodeWithSelector(EulerPauseResponse.UnknownTriggerType.selector, uint8(0)));
        vm.prank(trapManager);
        response.respond(badPayload);

        // Trigger type out of range (99) is rejected
        bytes memory outOfRange = abi.encode(uint8(99), uint256(0), uint256(0), uint256(0));
        vm.expectRevert(abi.encodeWithSelector(EulerPauseResponse.UnknownTriggerType.selector, uint8(99)));
        vm.prank(trapManager);
        response.respond(outOfRange);
    }

    // [9] Response contract refuses ReadFailureAlertOnly: shouldAlert can emit
    //     it for monitoring, but it must never auto-pause the protocol.
    function test_ResponseRejectsReadFailureAlertOnly() public {
        bytes memory readFailurePayload = abi.encode(
            uint8(EulerFinanceTrap.TriggerType.ReadFailureAlertOnly),
            uint256(0),
            uint256(0),
            uint256(block.number)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                EulerPauseResponse.UnknownTriggerType.selector,
                uint8(EulerFinanceTrap.TriggerType.ReadFailureAlertOnly)
            )
        );
        vm.prank(trapManager);
        response.respond(readFailurePayload);
    }

    // [10] Oversized payloads (5+ encoded fields) are rejected before decoding.
    function test_ResponseRejectsOversizedPayload() public {
        bytes memory oversized = abi.encode(
            uint8(EulerFinanceTrap.TriggerType.BadDebt),
            uint256(1),
            uint256(1),
            uint256(block.number),
            uint256(999)
        );

        vm.expectRevert(EulerPauseResponse.InvalidPayload.selector);
        vm.prank(trapManager);
        response.respond(oversized);
    }

    function _validBadDebtPayload() internal pure returns (bytes memory) {
        return abi.encode(
            uint8(EulerFinanceTrap.TriggerType.BadDebt),
            uint256(1e18),
            uint256(1),
            uint256(16_818_057)
        );
    }
}
