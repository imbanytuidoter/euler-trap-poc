// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Trap} from "drosera-contracts/Trap.sol";
import {EventLog, EventFilter} from "drosera-contracts/libraries/Events.sol";
import "./interfaces/IEulerMarket.sol";

/// @title EulerFinanceTrap
/// @notice Mock-production Drosera Trap that detects Euler-style bad debt and
///         reserve-donation anomalies on a single configured market.
///
/// Important scope:
/// - This is not a byte-for-byte reconstruction of Euler v1.
/// - It detects bad debt only across accounts discovered from recent event logs.
/// - It does not claim to interrupt an already-atomic transaction during execution.
/// - It can fire a response as soon as a broken invariant becomes observable.
///
/// Encoding note: CollectOutput uses uint256 for the read-ok flags instead of
/// bool. `abi.decode(..., bool)` reverts on any word whose value is not 0 or 1,
/// which means a same-length-but-non-canonical sample could revert the trap
/// outside our own error paths. uint256 flags treat any non-zero as "ok" and
/// can absorb arbitrary input without reverting.
contract EulerFinanceTrap is Trap {
    // Real Euler v1 markets contract on Ethereum mainnet (pre-exploit).
    // Tests etch MockEulerMarket bytecode at this address.
    address public constant EULER_MARKET = 0x27182842E098f60e3D576794A5bFFb0777E025d3;

    uint256 public constant RESERVE_SPIKE_BPS = 5_000; // 50%
    uint256 public constant ABSOLUTE_RESERVE_SPIKE = 1_000_000e18; // 1M units
    uint256 public constant MIN_SAMPLE_SIZE = 5;
    uint256 public constant MAX_SAMPLE_SIZE = 10;
    uint256 public constant MAX_WINDOW_BLOCKS = 32;

    uint256 private constant BPS = 10_000;
    uint256 private constant MAX_ACCOUNTS = 32;
    // CollectOutput abi-encodes to exactly 8 fields × 32 bytes.
    uint256 private constant COLLECT_OUTPUT_SIZE = 8 * 32;
    // shouldRespond / shouldAlert payloads are exactly 4 fields × 32 bytes.
    uint256 private constant ALERT_PAYLOAD_SIZE = 4 * 32;

    bytes32 private constant DEPOSIT_SIG = keccak256("Deposit(address,uint256)");
    bytes32 private constant BORROW_SIG = keccak256("Borrow(address,uint256)");
    bytes32 private constant MINT_SIG = keccak256("Mint(address,uint256,uint256)");
    bytes32 private constant DONATE_SIG = keccak256("DonateToReserves(address,uint256)");
    bytes32 private constant LIQUIDATE_SIG = keccak256("Liquidate(address,address,uint256,uint256,uint256)");

    uint256 private constant FLAG_FALSE = 0;
    uint256 private constant FLAG_TRUE = 1;

    /// @notice Trigger categories. ReadFailureAlertOnly is intentionally non-actionable:
    ///         shouldRespond ignores it, shouldAlert emits it for monitoring,
    ///         the response contract rejects it.
    enum TriggerType {
        None,
        BadDebt,
        ReserveVelocity,
        AbsoluteReserveSpike,
        ReadFailureAlertOnly
    }

    /// @dev Read-ok fields are uint256 (not bool) so abi.decode cannot revert
    ///      on a same-length-but-non-canonical sample. Any non-zero value
    ///      means "ok"; zero means "read failed".
    struct CollectOutput {
        uint256 totalReserves;
        uint256 totalBorrows;
        uint256 blockNumber;
        uint256 sampledBadDebt;
        uint256 unhealthyAccountCount;
        uint256 reservesReadOk;
        uint256 borrowsReadOk;
        uint256 accountReadsOk;
    }

    /// @dev Fixed-size accumulator for discovered accounts. Lives in memory only.
    struct DiscoverySet {
        address[MAX_ACCOUNTS] accounts;
        uint256 count;
    }

    error InvalidAlertPayload();

    constructor() {}

    /// @notice Event filters consumed by Drosera operators.
    /// @dev Order here is just for human readability; the actual
    ///      account-discovery prioritization is enforced inside collect().
    function eventLogFilters() public pure override returns (EventFilter[] memory filters) {
        filters = new EventFilter[](5);
        filters[0] = EventFilter({contractAddress: EULER_MARKET, signature: "DonateToReserves(address,uint256)"});
        filters[1] = EventFilter({
            contractAddress: EULER_MARKET, signature: "Liquidate(address,address,uint256,uint256,uint256)"
        });
        filters[2] = EventFilter({contractAddress: EULER_MARKET, signature: "Mint(address,uint256,uint256)"});
        filters[3] = EventFilter({contractAddress: EULER_MARKET, signature: "Borrow(address,uint256)"});
        filters[4] = EventFilter({contractAddress: EULER_MARKET, signature: "Deposit(address,uint256)"});
    }

    function collect() external view override returns (bytes memory) {
        IEulerMarket market = IEulerMarket(EULER_MARKET);

        DiscoverySet memory discovered = _discoverAccountsPrioritized();

        uint256 sampledBadDebt = 0;
        uint256 unhealthyAccountCount = 0;
        uint256 accountReadsOk = FLAG_TRUE;

        // Bounded loop: discovered.count <= MAX_ACCOUNTS = 32. External calls
        // here are a Drosera operator's view-context shadow-fork eth_call;
        // there's no on-chain gas to conserve and try/catch isolates each read.
        for (uint256 i = 0; i < discovered.count; i++) {
            // slither-disable-next-line calls-loop
            try market.getAccountLiquidity(discovered.accounts[i]) returns (
                uint256 collateralValue, uint256 liabilityValue
            ) {
                if (liabilityValue > collateralValue) {
                    // Checked addition: with realistic Euler-scale values
                    // (TVL ~ 2e26 wei) summed over MAX_ACCOUNTS this cannot
                    // overflow, but a checked-add is still preferable to a
                    // silent wrap on adversarial mock inputs.
                    sampledBadDebt += liabilityValue - collateralValue;
                    unhealthyAccountCount++;
                }
            } catch {
                accountReadsOk = FLAG_FALSE;
            }
        }

        uint256 reserves = 0;
        uint256 borrows = 0;
        uint256 reservesReadOk = FLAG_FALSE;
        uint256 borrowsReadOk = FLAG_FALSE;

        try market.totalReserves() returns (uint256 r) {
            reserves = r;
            reservesReadOk = FLAG_TRUE;
        } catch {}
        try market.totalBorrows() returns (uint256 b) {
            borrows = b;
            borrowsReadOk = FLAG_TRUE;
        } catch {}

        return abi.encode(
            CollectOutput({
                totalReserves: reserves,
                totalBorrows: borrows,
                blockNumber: block.number,
                sampledBadDebt: sampledBadDebt,
                unhealthyAccountCount: unhealthyAccountCount,
                reservesReadOk: reservesReadOk,
                borrowsReadOk: borrowsReadOk,
                accountReadsOk: accountReadsOk
            })
        );
    }

    /// @notice Auto-pause path. Read failures are intentionally ignored here —
    ///         a failed read is alert-only material via shouldAlert(), not
    ///         grounds to halt the protocol.
    ///
    /// Order of checks is deliberate:
    /// 1. Length and per-sample validity (cheap structural rejection).
    /// 2. Window validity (block ordering + span).
    /// 3. Current-sample read flags — a degraded current sample cannot fire
    ///    an auto-pause; it routes through shouldAlert() instead.
    /// 4. BadDebt — depends only on current sampledBadDebt.
    /// 5. Base-sample read flags — must be set before consulting base.
    ///    Without this, a failed base read looks like a zero-baseline and can
    ///    trigger a false AbsoluteReserveSpike.
    /// 6. ReserveVelocity / AbsoluteReserveSpike — both consult base.
    function shouldRespond(bytes[] calldata data) external pure override returns (bool, bytes memory) {
        if (data.length < MIN_SAMPLE_SIZE || data.length > MAX_SAMPLE_SIZE) {
            return (false, bytes(""));
        }
        if (!_validEncodedSample(data[0])) return (false, bytes(""));
        if (!_validEncodedSample(data[data.length - 1])) return (false, bytes(""));

        CollectOutput memory curr = abi.decode(data[0], (CollectOutput));
        CollectOutput memory base = abi.decode(data[data.length - 1], (CollectOutput));

        if (!_validWindow(curr, base)) return (false, bytes(""));

        if (!_currentReadsOk(curr)) {
            return (false, bytes(""));
        }

        if (curr.sampledBadDebt > 0) {
            return (
                true,
                abi.encode(
                    uint8(TriggerType.BadDebt), curr.sampledBadDebt, curr.unhealthyAccountCount, curr.blockNumber
                )
            );
        }

        // Velocity / spike checks require a trusted base sample. If the base
        // reads were degraded, treat base aggregates as unknown and bail.
        if (!_baseReadsOk(base)) {
            return (false, bytes(""));
        }

        if (base.totalReserves > 0 && curr.totalReserves > base.totalReserves) {
            uint256 reserveGrowthBps = ((curr.totalReserves - base.totalReserves) * BPS) / base.totalReserves;
            bool reserveSpike = reserveGrowthBps >= RESERVE_SPIKE_BPS;
            bool borrowsGrew = curr.totalBorrows > base.totalBorrows;
            if (reserveSpike && borrowsGrew) {
                return (
                    true,
                    abi.encode(
                        uint8(TriggerType.ReserveVelocity),
                        reserveGrowthBps,
                        curr.totalBorrows - base.totalBorrows,
                        curr.blockNumber
                    )
                );
            }
        }

        if (
            base.totalReserves == 0 && curr.totalReserves >= ABSOLUTE_RESERVE_SPIKE
                && curr.totalBorrows > base.totalBorrows
        ) {
            return (
                true,
                abi.encode(
                    uint8(TriggerType.AbsoluteReserveSpike),
                    curr.totalReserves,
                    curr.totalBorrows - base.totalBorrows,
                    curr.blockNumber
                )
            );
        }

        return (false, bytes(""));
    }

    /// @notice Alert-only path. Currently emits ReadFailureAlertOnly when any
    ///         market read failed. Operators / humans can subscribe without
    ///         exposing the protocol to false-positive auto-pauses.
    function shouldAlert(bytes[] calldata data) external pure override returns (bool, bytes memory) {
        if (data.length == 0) return (false, bytes(""));
        if (!_validEncodedSample(data[0])) return (false, bytes(""));

        CollectOutput memory curr = abi.decode(data[0], (CollectOutput));

        if (!_currentReadsOk(curr)) {
            return (true, abi.encode(uint8(TriggerType.ReadFailureAlertOnly), uint256(0), uint256(0), curr.blockNumber));
        }

        return (false, bytes(""));
    }

    /// @notice Decodes a typed alert/response payload for off-chain consumers.
    /// @dev Reverts with InvalidAlertPayload on wrong length before attempting
    ///      abi.decode. The first word is decoded as uint256 and then
    ///      narrowed to uint8 manually, so a same-length-but-non-canonical
    ///      uint8 word cannot revert outside our own error path.
    function decodeAlertOutput(bytes calldata payload)
        external
        pure
        returns (uint8 triggerType, uint256 metric1, uint256 metric2, uint256 blockNumber)
    {
        if (payload.length != ALERT_PAYLOAD_SIZE) revert InvalidAlertPayload();
        uint256 rawTriggerType;
        (rawTriggerType, metric1, metric2, blockNumber) = abi.decode(payload, (uint256, uint256, uint256, uint256));
        triggerType = uint8(rawTriggerType);
    }

    // ---------- internal helpers ----------

    /// @dev Walks the recent event log set in priority order so that
    ///      attack-relevant signatures (Donate / Liquidate violator / Mint)
    ///      take cap slots before noisier Deposit/Borrow activity can fill it.
    function _discoverAccountsPrioritized() internal view returns (DiscoverySet memory discovered) {
        EventLog[] memory logs = getEventLogs();

        discovered = _collectBySignature(logs, discovered, DONATE_SIG, 1);
        discovered = _collectBySignature(logs, discovered, LIQUIDATE_SIG, 2);
        discovered = _collectBySignature(logs, discovered, MINT_SIG, 1);
        discovered = _collectBySignature(logs, discovered, BORROW_SIG, 1);
        discovered = _collectBySignature(logs, discovered, DEPOSIT_SIG, 1);
        // Liquidator addresses last — they're the responder, not the offender
        discovered = _collectBySignature(logs, discovered, LIQUIDATE_SIG, 1);
    }

    function _collectBySignature(
        EventLog[] memory logs,
        DiscoverySet memory discovered,
        bytes32 signature,
        uint256 topicIndex
    ) internal pure returns (DiscoverySet memory) {
        for (uint256 i = 0; i < logs.length && discovered.count < MAX_ACCOUNTS; i++) {
            if (logs[i].emitter != EULER_MARKET) continue;
            if (logs[i].topics.length == 0) continue;
            if (logs[i].topics[0] != signature) continue;
            if (logs[i].topics.length <= topicIndex) continue;

            address account = _addressFromTopic(logs[i].topics[topicIndex]);
            discovered.count = _addUnique(discovered.accounts, discovered.count, account);
        }
        return discovered;
    }

    /// @dev Exact-length check. abi.decode of all-uint256 fields from a
    ///      buffer of exactly this size cannot revert on field content.
    function _validEncodedSample(bytes calldata sample) internal pure returns (bool) {
        return sample.length == COLLECT_OUTPUT_SIZE;
    }

    /// @dev Window validation:
    ///      - Both samples must carry a non-zero block number (a zero-encoded
    ///        sample would otherwise look like a chain-genesis ghost).
    ///      - `curr` must strictly follow `base` (newest-first ordering).
    ///      - Span between samples must not exceed MAX_WINDOW_BLOCKS so an
    ///        old stale `base` cannot be paired with a fresh `curr`.
    function _validWindow(CollectOutput memory curr, CollectOutput memory base) internal pure returns (bool) {
        if (curr.blockNumber == 0 || base.blockNumber == 0) return false;
        if (curr.blockNumber <= base.blockNumber) return false;
        if (curr.blockNumber - base.blockNumber > MAX_WINDOW_BLOCKS) return false;
        return true;
    }

    /// @dev All three current-sample read flags must be set for any
    ///      response-firing trigger.
    function _currentReadsOk(CollectOutput memory out) internal pure returns (bool) {
        return out.reservesReadOk == FLAG_TRUE && out.borrowsReadOk == FLAG_TRUE && out.accountReadsOk == FLAG_TRUE;
    }

    /// @dev Base sample only needs the aggregate reads (totalReserves,
    ///      totalBorrows) to support velocity / absolute-spike comparisons.
    ///      Account-level reads are not consulted on the base side, so
    ///      accountReadsOk is not required here.
    function _baseReadsOk(CollectOutput memory out) internal pure returns (bool) {
        return out.reservesReadOk == FLAG_TRUE && out.borrowsReadOk == FLAG_TRUE;
    }

    function _addressFromTopic(bytes32 topic) internal pure returns (address) {
        return address(uint160(uint256(topic)));
    }

    function _addUnique(address[MAX_ACCOUNTS] memory accounts, uint256 count, address account)
        internal
        pure
        returns (uint256)
    {
        if (account == address(0)) return count;
        for (uint256 i = 0; i < count; i++) {
            if (accounts[i] == account) return count;
        }
        if (count >= MAX_ACCOUNTS) return count;
        accounts[count] = account;
        return count + 1;
    }
}
