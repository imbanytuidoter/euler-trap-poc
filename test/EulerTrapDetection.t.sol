// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/EulerFinanceTrap.sol";
import "../src/mocks/MockEulerMarket.sol";
import "../src/response/EulerPauseResponse.sol";

// Verifies that the Trap detects each attack phase and that the response
// contract correctly halts the market when triggered.

contract EulerTrapDetection is Test {

    MockEulerMarket    public euler;
    EulerFinanceTrap   public trap;
    EulerPauseResponse public response;

    address public alice      = makeAddr("alice");
    address public bob        = makeAddr("bob");
    address public atk1       = makeAddr("atk1");
    address public atk2       = makeAddr("atk2");
    address public trapManager = makeAddr("trapManager");

    uint256 constant ONE_M = 1_000_000 * 1e18;
    uint256 constant CF    = 7500;
    uint256 constant BPS   = 10_000;

    address[] public trackedAccounts;

    function setUp() public {
        euler = new MockEulerMarket();

        trackedAccounts = new address[](4);
        trackedAccounts[0] = alice;
        trackedAccounts[1] = bob;
        trackedAccounts[2] = atk1;
        trackedAccounts[3] = atk2;

        trap     = new EulerFinanceTrap(address(euler), trackedAccounts);
        response = new EulerPauseResponse(address(euler), trapManager);

        vm.roll(16_818_050);

        vm.prank(alice);
        euler.deposit(30 * ONE_M);
        vm.prank(alice);
        euler.borrow(20 * ONE_M);

        vm.prank(bob);
        euler.deposit(20 * ONE_M);
        vm.prank(bob);
        euler.borrow(10 * ONE_M);
    }

    function _buildWindow(bytes[] memory oldestFirst)
        internal pure
        returns (bytes[] memory newestFirst)
    {
        uint256 n = oldestFirst.length;
        newestFirst = new bytes[](n);
        for (uint256 i; i < n; i++) {
            newestFirst[i] = oldestFirst[n - 1 - i];
        }
    }

    function _cleanBaseline() internal view returns (bytes memory) {
        return abi.encode(
            EulerFinanceTrap.CollectOutput({
                totalBadDebt  : 0,
                totalReserves : 0,
                totalBorrows  : 30 * ONE_M,
                blockNumber   : block.number - 5
            })
        );
    }

    // [1] No false positives during normal operation
    function test_NoFalsePositive_NormalOperation() public {
        bytes[] memory window = new bytes[](5);
        for (uint256 i; i < 5; i++) {
            window[i] = trap.collect();
            vm.roll(block.number + 1);
        }
        (bool triggered, ) = trap.shouldRespond(_buildWindow(window));
        assertFalse(triggered, "MUST NOT trigger on normal operation");
        console.log("[OK] No false positive across 5 normal blocks");
    }

    // [2] Invariant 1 fires when bad debt appears
    function test_Invariant1_BadDebt_TriggersShouldRespond() public {
        bytes[] memory window = new bytes[](5);

        for (uint256 i; i < 3; i++) {
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

        window[3] = trap.collect();
        vm.roll(block.number + 1);
        window[4] = trap.collect();

        (bool triggered, bytes memory payload) = trap.shouldRespond(_buildWindow(window));
        assertTrue(triggered, "shouldRespond() MUST return true when bad debt exists");

        (string memory reason, uint256 badDebt, uint256 blockNum) =
            abi.decode(payload, (string, uint256, uint256));

        console.log("[TRIGGERED]", reason);
        console.log("  bad debt:", badDebt);
        console.log("  at block:", blockNum);

        assertGt(badDebt, 0);
        assertEq(
            keccak256(bytes(reason)),
            keccak256(bytes("TRIGGERED: BadDebtInvariantBroke()"))
        );
    }

    // [3] Invariant 2 fires before bad debt exists.
    //
    // Attacker deposits 500M, borrows 100M (HF = 3.0), donates 40M to reserves.
    // Position stays solvent: col = 460M * 75% = 345M > liab = 100M.
    // getTotalBadDebt() == 0, so Invariant 1 is silent.
    // Reserves jump from 5M baseline to 40M (+700%) — Invariant 2 triggers.
    function test_Invariant2_ReserveVelocity_TriggersShouldRespond() public {
        // Baseline: protocol already has some reserves from normal interest
        bytes[] memory window = new bytes[](2);
        window[1] = abi.encode(
            EulerFinanceTrap.CollectOutput({
                totalBadDebt  : 0,
                totalReserves : 5 * ONE_M,
                totalBorrows  : 30 * ONE_M,
                blockNumber   : block.number - 3
            })
        );

        // Attacker builds position with large collateral buffer, then donates.
        // eTokens: 500M - 40M = 460M  →  col = 460M * 75% = 345M
        // dTokens: 100M               →  liab = 100M
        // HF = 3.45 → position is SOLVENT → getTotalBadDebt() == 0
        vm.startPrank(atk1);
        euler.deposit(500 * ONE_M);
        euler.borrow(100 * ONE_M);
        euler.donateToReserves(40 * ONE_M);
        vm.stopPrank();

        // curr.totalReserves = 40M, base.totalReserves = 5M
        // reserveGrowthBps = (40-5)*10000/5 = 70_000 >= 5_000  ✓
        // borrowsGrew = 130M > 30M  ✓
        // totalBadDebt == 0  →  Invariant 1 silent, Invariant 2 fires  ✓
        window[0] = trap.collect();

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "shouldRespond() MUST trigger on velocity anomaly");

        (string memory reason, uint256 growthBps, uint256 borrowIncrease, ) =
            abi.decode(payload, (string, uint256, uint256, uint256));

        console.log("[TRIGGERED - EARLY WARNING]", reason);
        console.log("  reserve growth BPS:", growthBps);
        console.log("  borrow increase (wei):", borrowIncrease);

        assertEq(
            keccak256(bytes(reason)),
            keccak256(bytes("TRIGGERED: DonationAttackVelocityAnomaly()"))
        );
        assertGe(growthBps, 5_000);
        assertGt(borrowIncrease, 0);
    }

    // [4] Full end-to-end mitigation
    function test_FullMitigation_AttackerCannotExit() public {
        vm.startPrank(atk1);
        euler.mint(150 * ONE_M, 150 * ONE_M * CF / BPS);
        euler.donateToReserves(100 * ONE_M);
        vm.stopPrank();
        vm.prank(atk2);
        euler.liquidate(atk1, 375 * 1e5 * 1e18);

        bytes[] memory window = new bytes[](2);
        window[0] = trap.collect();
        window[1] = _cleanBaseline();

        (bool triggered, bytes memory payload) = trap.shouldRespond(window);
        assertTrue(triggered, "trap must fire");

        // Drosera operator calls respond()
        vm.prank(trapManager);
        response.respond(payload);
        assertTrue(euler.paused(), "market must be paused");

        // Attacker cannot exit
        vm.expectRevert("MockEuler: market paused");
        vm.prank(atk2);
        euler.borrow(1);

        vm.expectRevert("MockEuler: market paused");
        vm.prank(atk2);
        euler.deposit(1);

        (uint256 atk2Collateral, ) = euler.getAccountLiquidity(atk2);
        assertGt(atk2Collateral, 0, "attacker funds are locked");

        console.log("=== MITIGATION COMPLETE ===");
        console.log("Market paused:", euler.paused());
        console.log("Attacker locked collateral:", atk2Collateral);
        console.log("Attacker successful exits: 0");
    }

    // [5] < 2 samples → no trigger
    function test_InsufficientWindow_NoTrigger() public {
        bytes[] memory window = new bytes[](1);
        window[0] = trap.collect();
        (bool triggered, ) = trap.shouldRespond(window);
        assertFalse(triggered);
    }

    // [6] Only trapManager can call respond()
    function test_ResponseAuthorization_OnlyTrapManager() public {
        vm.expectRevert(
            abi.encodeWithSelector(EulerPauseResponse.OnlyTrapManager.selector, address(this))
        );
        response.respond(bytes(""));
    }
}
