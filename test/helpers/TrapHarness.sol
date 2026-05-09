// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/EulerFinanceTrap.sol";
import "../../src/mocks/MockEulerMarket.sol";
import {EventLog} from "drosera-contracts/libraries/Events.sol";

// Shared harness that mirrors how Drosera deploys and feeds a Trap:
//   - The Trap is deployed without arguments at a test-local address.
//   - MockEulerMarket bytecode is etched at the hardcoded EULER_MARKET
//     address so the Trap reads from the same contract its constants point at.
//   - Helper functions record events emitted by the mock and push them into
//     the Trap's _eventLogs storage via setEventLogs(), simulating what the
//     Drosera Operator does on each block.
abstract contract TrapHarness is Test {

    EulerFinanceTrap public trap;
    MockEulerMarket  public euler;
    address          public eulerAddr;

    function _deployHarness() internal {
        trap      = new EulerFinanceTrap();
        eulerAddr = trap.EULER_MARKET();

        MockEulerMarket impl = new MockEulerMarket();
        vm.etch(eulerAddr, address(impl).code);
        euler = MockEulerMarket(eulerAddr);

        vm.recordLogs();
    }

    // Capture every log emitted since the last drain, push to the Trap.
    // setEventLogs() appends, so the Trap accumulates discoverable accounts.
    function _flushLogsToTrap() internal {
        Vm.Log[] memory recorded = vm.getRecordedLogs();
        EventLog[] memory toFeed = new EventLog[](recorded.length);
        for (uint256 i = 0; i < recorded.length; i++) {
            toFeed[i] = EventLog({
                topics:  recorded[i].topics,
                data:    recorded[i].data,
                emitter: recorded[i].emitter
            });
        }
        trap.setEventLogs(toFeed);
    }

    // Return data[] in newest-first order, as Drosera passes it to shouldRespond().
    function _newestFirst(bytes[] memory oldestFirst) internal pure returns (bytes[] memory) {
        uint256 n = oldestFirst.length;
        bytes[] memory out = new bytes[](n);
        for (uint256 i = 0; i < n; i++) out[i] = oldestFirst[n - 1 - i];
        return out;
    }

    // Hand-built oldest-block snapshot used to anchor a window without
    // running a full N-block setup (when the test only needs base vs current).
    function _cleanBaselineEncoded() internal view returns (bytes memory) {
        return abi.encode(EulerFinanceTrap.CollectOutput({
            totalReserves         : 0,
            totalBorrows          : 0,
            blockNumber           : block.number > 5 ? block.number - 5 : 0,
            sampledBadDebt        : 0,
            unhealthyAccountCount : 0,
            reservesReadOk        : true,
            borrowsReadOk         : true,
            accountReadsOk        : true
        }));
    }

    function _baselineWithReserves(uint256 reserves, uint256 borrows)
        internal view
        returns (bytes memory)
    {
        return abi.encode(EulerFinanceTrap.CollectOutput({
            totalReserves         : reserves,
            totalBorrows          : borrows,
            blockNumber           : block.number > 5 ? block.number - 5 : 0,
            sampledBadDebt        : 0,
            unhealthyAccountCount : 0,
            reservesReadOk        : true,
            borrowsReadOk         : true,
            accountReadsOk        : true
        }));
    }

    // 5-element window with a single fresh sample at index 0 and four
    // identical clean baselines after it. Useful when the only thing under
    // test is "current block triggers, everything else was clean".
    function _windowWithCurrent(bytes memory current) internal view returns (bytes[] memory) {
        bytes[] memory w = new bytes[](5);
        w[0] = current;
        w[1] = _cleanBaselineEncoded();
        w[2] = _cleanBaselineEncoded();
        w[3] = _cleanBaselineEncoded();
        w[4] = _cleanBaselineEncoded();
        return w;
    }

    function _windowWithCurrentAndBase(bytes memory current, bytes memory base)
        internal view
        returns (bytes[] memory)
    {
        bytes[] memory w = new bytes[](5);
        w[0] = current;
        w[1] = _cleanBaselineEncoded();
        w[2] = _cleanBaselineEncoded();
        w[3] = _cleanBaselineEncoded();
        w[4] = base;
        return w;
    }
}
