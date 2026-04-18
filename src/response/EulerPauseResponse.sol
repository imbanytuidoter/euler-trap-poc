// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/IEulerMarket.sol";

// Called by Drosera TrapManager when operator quorum confirms shouldRespond() = true.
// response_contract in drosera.toml points here.
// response_function = "respond(bytes)"

contract EulerPauseResponse {

    address public immutable EULER_MARKET;
    address public immutable DROSERA_TRAP_MANAGER;

    event ProtocolPaused(bytes triggerPayload, uint256 blockNumber);

    error OnlyTrapManager(address caller);
    error AlreadyPaused();

    constructor(address market, address trapManager) {
        EULER_MARKET         = market;
        DROSERA_TRAP_MANAGER = trapManager;
    }

    // payload = abi-encoded trigger data from shouldRespond()
    // e.g. abi.encode("TRIGGERED: BadDebtInvariantBroke()", badDebt, blockNumber)
    function respond(bytes calldata payload) external {
        if (msg.sender != DROSERA_TRAP_MANAGER) revert OnlyTrapManager(msg.sender);
        if (IEulerMarket(EULER_MARKET).paused())  revert AlreadyPaused();

        // [RESPONSE LINE] Maps to TRAP LINE A or TRAP LINE B.
        // Halts all market operations — attacker cannot withdraw eTokens.
        IEulerMarket(EULER_MARKET).pause();

        emit ProtocolPaused(payload, block.number);
    }
}
