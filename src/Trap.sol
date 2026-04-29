// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Local mirror of the Drosera abstract Trap contract.
// Matches the canonical ITrap surface: collect() + shouldRespond() + eventLogFilters().
// Production source: https://github.com/drosera-network/drosera-contracts

struct EventLog {
    bytes32[] topics;
    bytes     data;
    address   emitter;
}

struct EventFilter {
    address contractAddress;
    string  signature;
}

abstract contract Trap {
    EventLog[] private _eventLogs;

    function collect() external view virtual returns (bytes memory);

    function shouldRespond(bytes[] calldata data)
        external view virtual returns (bool, bytes memory);

    function eventLogFilters() public view virtual returns (EventFilter[] memory) {
        return new EventFilter[](0);
    }

    function version() public pure returns (string memory) { return "2.0"; }

    function setEventLogs(EventLog[] calldata logs) public {
        for (uint256 i; i < logs.length; i++) {
            _eventLogs.push(EventLog({
                emitter: logs[i].emitter,
                topics:  logs[i].topics,
                data:    logs[i].data
            }));
        }
    }

    function getEventLogs() public view returns (EventLog[] memory) {
        return _eventLogs;
    }
}
