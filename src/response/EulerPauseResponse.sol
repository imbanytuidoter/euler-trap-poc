// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/IEulerMarket.sol";

/// @title EulerPauseResponse
/// @notice Called by the Drosera TrapManager when shouldRespond() returns true
///         on the operator quorum. Pauses the configured Euler market.
///
/// Payload (from EulerFinanceTrap.shouldRespond):
///   abi.encode(uint8 triggerType, uint256 metric1, uint256 metric2, uint256 atBlock)
///
/// Accepted triggerType values:
///   1 = BadDebt
///   2 = ReserveVelocity
///   3 = AbsoluteReserveSpike
///
/// Rejected here (deliberately):
///   0 = None
///   4 = ReadFailureAlertOnly  — alert-only signal, must not auto-pause the protocol
contract EulerPauseResponse {
    address public immutable EULER_MARKET;
    address public immutable DROSERA_TRAP_MANAGER;

    event ProtocolPaused(uint8 indexed triggerType, uint256 metric1, uint256 metric2, uint256 atBlock);

    error OnlyTrapManager(address caller);
    error AlreadyPaused();
    error UnknownTriggerType(uint8 triggerType);
    error InvalidPayload();
    error ZeroAddress();
    error PauseDidNotTakeEffect();

    constructor(address market, address trapManager) {
        if (market == address(0) || trapManager == address(0)) revert ZeroAddress();
        EULER_MARKET = market;
        DROSERA_TRAP_MANAGER = trapManager;
    }

    function respond(bytes calldata payload) external {
        if (msg.sender != DROSERA_TRAP_MANAGER) revert OnlyTrapManager(msg.sender);
        if (IEulerMarket(EULER_MARKET).paused()) revert AlreadyPaused();
        if (payload.length != 4 * 32) revert InvalidPayload();

        // Decode the first word as uint256 so a same-length-but-non-canonical
        // uint8 word cannot revert outside our own error paths. After the
        // bounds check, the value is safe to narrow to uint8 for emission.
        (uint256 rawTriggerType, uint256 metric1, uint256 metric2, uint256 atBlock) =
            abi.decode(payload, (uint256, uint256, uint256, uint256));

        // 0 (None) and >3 (currently only 4 = ReadFailureAlertOnly) are rejected.
        if (rawTriggerType == 0 || rawTriggerType > 3) {
            revert UnknownTriggerType(uint8(rawTriggerType));
        }

        uint8 triggerType = uint8(rawTriggerType);

        // EULER_MARKET is an immutable pointer set at construction; we treat it
        // as a trusted target. The post-call event emission is intentional —
        // we want the event to mark a successful pause, not an attempted one.
        // slither-disable-next-line reentrancy-events
        IEulerMarket(EULER_MARKET).pause();

        // Post-condition: confirm pause() actually took effect. If the target
        // silently no-ops (proxy upgrade, governance change, mis-wired clone),
        // we surface that as PauseDidNotTakeEffect rather than emit a misleading
        // ProtocolPaused event.
        if (!IEulerMarket(EULER_MARKET).paused()) {
            revert PauseDidNotTakeEffect();
        }

        emit ProtocolPaused(triggerType, metric1, metric2, atBlock);
    }
}
