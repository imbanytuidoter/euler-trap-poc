// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/IEulerMarket.sol";

// Called by Drosera TrapManager when operator quorum confirms shouldRespond() = true.
// response_contract in drosera.toml points here.
// response_function = "respond(bytes)"
//
// Payload format (from EulerFinanceTrap.shouldRespond):
//   abi.encode(uint8 triggerType, uint256 metric1, uint256 metric2, uint256 blockNumber)
//
// triggerType maps to EulerFinanceTrap.TriggerType:
//   1 = BadDebt              (metric1 = badDebtAmount, metric2 = unhealthyAccountCount)
//   2 = ReserveVelocity      (metric1 = growthBps,     metric2 = borrowIncrease)
//   3 = AbsoluteReserveSpike (metric1 = totalReserves, metric2 = borrowIncrease)
//   4 = ReadFailure          (metric1 = 0,             metric2 = 0)

contract EulerPauseResponse {

    address public immutable EULER_MARKET;
    address public immutable DROSERA_TRAP_MANAGER;

    event ProtocolPaused(uint8 indexed triggerType, uint256 metric1, uint256 metric2, uint256 atBlock);

    error OnlyTrapManager(address caller);
    error AlreadyPaused();
    error UnknownTriggerType(uint8 triggerType);
    error InvalidPayload();

    constructor(address market, address trapManager) {
        EULER_MARKET         = market;
        DROSERA_TRAP_MANAGER = trapManager;
    }

    function respond(bytes calldata payload) external {
        if (msg.sender != DROSERA_TRAP_MANAGER) revert OnlyTrapManager(msg.sender);
        if (IEulerMarket(EULER_MARKET).paused()) revert AlreadyPaused();
        if (payload.length < 4 * 32) revert InvalidPayload();

        (uint8 triggerType, uint256 metric1, uint256 metric2, uint256 atBlock) =
            abi.decode(payload, (uint8, uint256, uint256, uint256));

        // None=0, BadDebt=1, ReserveVelocity=2, AbsoluteReserveSpike=3, ReadFailure=4
        if (triggerType == 0 || triggerType > 4) revert UnknownTriggerType(triggerType);

        IEulerMarket(EULER_MARKET).pause();
        emit ProtocolPaused(triggerType, metric1, metric2, atBlock);
    }
}
