// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IEulerMarket {
    function totalBorrows() external view returns (uint256);
    function totalReserves() external view returns (uint256);

    function getAccountLiquidity(address account)
        external view
        returns (uint256 collateralValue, uint256 liabilityValue);

    function pause() external;
    function paused() external view returns (bool);
}
