// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Trap.sol";
import "./interfaces/IEulerMarket.sol";

// Drosera Trap — Euler Finance donateToReserves() exploit.
// March 13 2023, block 16818057, ~$197M.
//
// This Trap is deployed by Drosera Operators in REVM/shadow-fork without
// constructor arguments. EULER_MARKET is hardcoded; monitored accounts are
// discovered each block from recent event logs (Drosera's getEventLogs()).
//
// Detection layers:
//
// 1. ReadFailure (operational)
//    Any market read reverts → Trap fires immediately. A failed read is a
//    signal in itself; silently substituting zero produces false negatives.
//
// 2. BadDebt (hard invariant)
//    For each account discovered in recent Deposit/Borrow/Mint/Donate/Liquidate
//    events: if liabilityValue > collateralValue → bad debt.
//    Note: this is bad debt across DISCOVERED accounts only, not protocol-wide.
//    Protocol-wide bad debt detection requires a protocol-level aggregator
//    (which Euler v1 did not have).
//
// 3. ReserveVelocity (early warning)
//    reserveGrowth >= 50% over the sample window AND totalBorrows grew.
//    Catches the donation+leverage fingerprint before the position is liquidated.
//    Disabled when base.totalReserves == 0 (avoid div-by-zero).
//
// 4. AbsoluteReserveSpike (zero-baseline coverage)
//    If base.totalReserves == 0 and curr.totalReserves crosses an absolute
//    threshold while borrows grew. Closes the gap that ReserveVelocity opens
//    when reserves start at zero.

contract EulerFinanceTrap is Trap {

    // Real Euler v1 markets contract (Ethereum mainnet, pre-exploit).
    // Tests etch MockEulerMarket code at this address.
    address public constant EULER_MARKET = 0x27182842E098f60e3D576794A5bFFb0777E025d3;

    // Detection thresholds. Drosera deploys without args, so everything is constant.
    uint256 public constant RESERVE_SPIKE_BPS      = 5_000;        // 50%
    uint256 public constant ABSOLUTE_RESERVE_SPIKE = 1_000_000e18; // 1M units
    uint256 public constant MIN_SAMPLE_SIZE        = 5;            // matches drosera.toml

    uint256 private constant BPS          = 10_000;
    uint256 private constant MAX_ACCOUNTS = 32;

    bytes32 private constant DEPOSIT_SIG   = keccak256("Deposit(address,uint256)");
    bytes32 private constant BORROW_SIG    = keccak256("Borrow(address,uint256)");
    bytes32 private constant MINT_SIG      = keccak256("Mint(address,uint256,uint256)");
    bytes32 private constant DONATE_SIG    = keccak256("DonateToReserves(address,uint256)");
    bytes32 private constant LIQUIDATE_SIG = keccak256("Liquidate(address,address,uint256,uint256,uint256)");

    enum TriggerType {
        None,
        BadDebt,
        ReserveVelocity,
        AbsoluteReserveSpike,
        ReadFailure
    }

    struct CollectOutput {
        uint256 totalReserves;
        uint256 totalBorrows;
        uint256 blockNumber;

        uint256 sampledBadDebt;
        uint256 unhealthyAccountCount;

        bool reservesReadOk;
        bool borrowsReadOk;
        bool accountReadsOk;
    }

    constructor() {}

    // Subscribe to events that identify "recently active" Euler accounts.
    // Drosera Operators feed matching logs into _eventLogs each block; collect()
    // reads them via getEventLogs().
    function eventLogFilters()
        public pure override
        returns (EventFilter[] memory filters)
    {
        filters = new EventFilter[](5);
        filters[0] = EventFilter({ contractAddress: EULER_MARKET, signature: "Deposit(address,uint256)" });
        filters[1] = EventFilter({ contractAddress: EULER_MARKET, signature: "Borrow(address,uint256)"  });
        filters[2] = EventFilter({ contractAddress: EULER_MARKET, signature: "Mint(address,uint256,uint256)" });
        filters[3] = EventFilter({ contractAddress: EULER_MARKET, signature: "DonateToReserves(address,uint256)" });
        filters[4] = EventFilter({ contractAddress: EULER_MARKET, signature: "Liquidate(address,address,uint256,uint256,uint256)" });
    }

    function collect() external view override returns (bytes memory) {
        IEulerMarket market = IEulerMarket(EULER_MARKET);

        // 1. Discover accounts from recent event logs (capped at MAX_ACCOUNTS).
        address[MAX_ACCOUNTS] memory discovered;
        uint256 count;
        EventLog[] memory logs = getEventLogs();
        for (uint256 i = 0; i < logs.length && count < MAX_ACCOUNTS; i++) {
            if (logs[i].emitter != EULER_MARKET) continue;
            if (logs[i].topics.length < 2) continue;

            bytes32 sig = logs[i].topics[0];
            if (sig == DEPOSIT_SIG || sig == BORROW_SIG || sig == MINT_SIG || sig == DONATE_SIG) {
                count = _addUnique(discovered, count, _addressFromTopic(logs[i].topics[1]));
            } else if (sig == LIQUIDATE_SIG && logs[i].topics.length >= 3) {
                count = _addUnique(discovered, count, _addressFromTopic(logs[i].topics[1])); // liquidator
                if (count < MAX_ACCOUNTS) {
                    count = _addUnique(discovered, count, _addressFromTopic(logs[i].topics[2])); // violator
                }
            }
        }

        // 2. Per-account liquidity. Read failure on ANY account flips accountReadsOk.
        uint256 sampledBadDebt;
        uint256 unhealthyAccountCount;
        bool accountReadsOk = true;
        for (uint256 i = 0; i < count; i++) {
            try market.getAccountLiquidity(discovered[i]) returns (uint256 col, uint256 liab) {
                if (liab > col) {
                    unchecked {
                        sampledBadDebt += liab - col;
                    }
                    unhealthyAccountCount++;
                }
            } catch {
                accountReadsOk = false;
            }
        }

        // 3. Protocol aggregates with explicit success flags. Failure ≠ zero.
        uint256 reserves;
        uint256 borrows;
        bool reservesReadOk;
        bool borrowsReadOk;
        try market.totalReserves() returns (uint256 r) { reserves = r; reservesReadOk = true; } catch {}
        try market.totalBorrows()  returns (uint256 b) { borrows  = b; borrowsReadOk  = true; } catch {}

        return abi.encode(CollectOutput({
            totalReserves         : reserves,
            totalBorrows          : borrows,
            blockNumber           : block.number,
            sampledBadDebt        : sampledBadDebt,
            unhealthyAccountCount : unhealthyAccountCount,
            reservesReadOk        : reservesReadOk,
            borrowsReadOk         : borrowsReadOk,
            accountReadsOk        : accountReadsOk
        }));
    }

    // data is newest-first: data[0] = current block, data[len-1] = oldest.
    // Requires MIN_SAMPLE_SIZE samples — threshold semantics depend on a fixed window.
    function shouldRespond(bytes[] calldata data)
        external pure override
        returns (bool, bytes memory)
    {
        if (data.length < MIN_SAMPLE_SIZE) return (false, bytes(""));

        CollectOutput memory curr = abi.decode(data[0],                (CollectOutput));
        CollectOutput memory base = abi.decode(data[data.length - 1], (CollectOutput));

        // Layer 1 — read failure dominates everything else.
        if (!curr.reservesReadOk || !curr.borrowsReadOk || !curr.accountReadsOk) {
            return (true, abi.encode(
                uint8(TriggerType.ReadFailure),
                uint256(0),
                uint256(0),
                curr.blockNumber
            ));
        }

        // Layer 2 — bad debt across discovered accounts.
        if (curr.sampledBadDebt > 0) {
            return (true, abi.encode(
                uint8(TriggerType.BadDebt),
                curr.sampledBadDebt,
                curr.unhealthyAccountCount,
                curr.blockNumber
            ));
        }

        // Layer 3 — relative reserve velocity (only when base reserves > 0).
        if (base.totalReserves > 0 && curr.totalReserves > base.totalReserves) {
            uint256 reserveGrowthBps =
                (curr.totalReserves - base.totalReserves) * BPS / base.totalReserves;
            bool reserveSpike = reserveGrowthBps >= RESERVE_SPIKE_BPS;
            bool borrowsGrew  = curr.totalBorrows > base.totalBorrows;
            if (reserveSpike && borrowsGrew) {
                return (true, abi.encode(
                    uint8(TriggerType.ReserveVelocity),
                    reserveGrowthBps,
                    curr.totalBorrows - base.totalBorrows,
                    curr.blockNumber
                ));
            }
        }

        // Layer 4 — absolute reserve spike from zero baseline.
        if (
            base.totalReserves == 0 &&
            curr.totalReserves >= ABSOLUTE_RESERVE_SPIKE &&
            curr.totalBorrows > base.totalBorrows
        ) {
            return (true, abi.encode(
                uint8(TriggerType.AbsoluteReserveSpike),
                curr.totalReserves,
                curr.totalBorrows - base.totalBorrows,
                curr.blockNumber
            ));
        }

        return (false, bytes(""));
    }

    // ---------- internal helpers ----------

    function _addressFromTopic(bytes32 topic) internal pure returns (address) {
        return address(uint160(uint256(topic)));
    }

    function _addUnique(
        address[MAX_ACCOUNTS] memory accounts,
        uint256 count,
        address account
    ) internal pure returns (uint256) {
        if (account == address(0)) return count;
        for (uint256 i = 0; i < count; i++) {
            if (accounts[i] == account) return count;
        }
        if (count >= MAX_ACCOUNTS) return count;
        accounts[count] = account;
        return count + 1;
    }
}
