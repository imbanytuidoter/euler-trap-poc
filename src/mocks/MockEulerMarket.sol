// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/IEulerMarket.sol";

// Euler Finance v1 — single-asset lending market.
// Collateral factor 75%, liquidation bonus 20%, matching pre-exploit on-chain params.
// Bad debt is derived from position accounting, not injected via flags.

contract MockEulerMarket is IEulerMarket {

    struct Position {
        uint256 eTokens;
        uint256 dTokens;
    }

    mapping(address => Position) public positions;

    uint256 private _totalBorrows;
    uint256 private _totalReserves;
    bool    private _paused;

    // Euler v1 risk parameters (from on-chain deployment, pre-exploit)
    uint256 public constant COLLATERAL_FACTOR_BPS = 7500;   // 75%
    uint256 public constant LIQUIDATION_BONUS_BPS = 2000;   // 20%
    uint256 private constant BPS = 10_000;

    event Deposit(address indexed account, uint256 amount);
    event Borrow(address indexed account, uint256 amount);
    event Mint(address indexed account, uint256 eAmount, uint256 dAmount);
    event DonateToReserves(address indexed account, uint256 amount);
    event Liquidate(address indexed liquidator, address indexed violator,
                    uint256 repaid, uint256 collateralTaken, uint256 badDebtCreated);
    event Withdraw(address indexed account, uint256 eTokenAmount);
    event Redeem(address indexed account, uint256 eTokenAmount);
    event Transfer(address indexed from, address indexed to, uint256 eTokenAmount);
    event Paused();

    modifier notPaused() {
        require(!_paused, "MockEuler: market paused");
        _;
    }

    function deposit(uint256 amount) external notPaused {
        require(amount > 0, "zero deposit");
        positions[msg.sender].eTokens += amount;
        emit Deposit(msg.sender, amount);
    }

    function borrow(uint256 amount) external notPaused {
        require(amount > 0, "zero borrow");
        positions[msg.sender].dTokens += amount;
        _totalBorrows += amount;
        (uint256 col, uint256 liab) = _accountLiquidity(msg.sender);
        require(col >= liab, "MockEuler: undercollateralized");
        emit Borrow(msg.sender, amount);
    }

    // Euler's leverage function: issues eTokens and dTokens atomically.
    // Single post-state solvency check. Attacker used this to build a
    // max-leverage position (HF = 1.0) before calling donateToReserves().
    function mint(uint256 eAmount, uint256 dAmount) external notPaused {
        require(eAmount > 0 || dAmount > 0, "zero mint");
        positions[msg.sender].eTokens += eAmount;
        positions[msg.sender].dTokens += dAmount;
        _totalBorrows += dAmount;
        (uint256 col, uint256 liab) = _accountLiquidity(msg.sender);
        require(col >= liab, "MockEuler: undercollateralized after mint");
        emit Mint(msg.sender, eAmount, dAmount);
    }

    // Attack vector: burns eToken collateral with no health-factor check.
    // dTokens are unchanged — HF = (eTokens * 0.75) / dTokens collapses.
    // Euler v1 had no solvency check after this call.
    // Exploit tx: 0xc310a0affe2169d1f6feec1c63dbc7f7c62a887ad5a5cdab7dc5d2b3c567e2d (block 16818057)
    function donateToReserves(uint256 amount) external notPaused {
        require(amount > 0, "zero donation");
        require(positions[msg.sender].eTokens >= amount, "MockEuler: insufficient eTokens");

        positions[msg.sender].eTokens -= amount;

        // Reserves spike — Trap signal
        _totalReserves += amount;

        // NO solvency check — this is the bug
        emit DonateToReserves(msg.sender, amount);
    }

    // Liquidator repays debt, receives collateral + 20% bonus.
    // If collateral < full bonus → shortfall = PROTOCOL BAD DEBT.
    function liquidate(address violator, uint256 repayAmount) external notPaused {
        require(violator != msg.sender, "self-liquidation requires separate EOA");
        require(repayAmount > 0, "zero repay");
        (uint256 col, uint256 liab) = _accountLiquidity(violator);
        require(liab > col, "MockEuler: position not liquidatable");
        require(positions[violator].dTokens >= repayAmount, "MockEuler: repay exceeds debt");

        uint256 collateralOwed = repayAmount * (BPS + LIQUIDATION_BONUS_BPS) / BPS;
        uint256 collateralAvailable = positions[violator].eTokens;
        uint256 collateralTransferred = collateralOwed <= collateralAvailable
            ? collateralOwed
            : collateralAvailable;

        positions[violator].dTokens -= repayAmount;
        _totalBorrows -= repayAmount;
        positions[violator].eTokens -= collateralTransferred;
        positions[msg.sender].eTokens += collateralTransferred;

        uint256 badDebtCreated = positions[violator].dTokens > 0 &&
                                 positions[violator].eTokens == 0
            ? positions[violator].dTokens : 0;

        emit Liquidate(msg.sender, violator, repayAmount, collateralTransferred, badDebtCreated);
    }

    // Withdraw the underlying represented by eTokens. This is the actual
    // exit path an attacker uses to extract stolen collateral.
    // Solvency-guarded: cannot leave the position underwater.
    function withdraw(uint256 eTokenAmount) external notPaused {
        require(eTokenAmount > 0, "zero withdraw");
        require(positions[msg.sender].eTokens >= eTokenAmount, "MockEuler: insufficient eTokens");
        positions[msg.sender].eTokens -= eTokenAmount;
        (uint256 col, uint256 liab) = _accountLiquidity(msg.sender);
        require(col >= liab, "MockEuler: undercollateralized after withdraw");
        emit Withdraw(msg.sender, eTokenAmount);
    }

    // Redeem eTokens for the underlying asset. Same effective path as withdraw
    // for this single-asset mock; kept separate to mirror Euler v1 surface.
    function redeem(uint256 eTokenAmount) external notPaused {
        require(eTokenAmount > 0, "zero redeem");
        require(positions[msg.sender].eTokens >= eTokenAmount, "MockEuler: insufficient eTokens");
        positions[msg.sender].eTokens -= eTokenAmount;
        (uint256 col, uint256 liab) = _accountLiquidity(msg.sender);
        require(col >= liab, "MockEuler: undercollateralized after redeem");
        emit Redeem(msg.sender, eTokenAmount);
    }

    // eToken transfer — secondary exit path (move stolen tokens to another EOA
    // or a CEX before the protocol can pause). Must also be blocked.
    function transferEToken(address to, uint256 eTokenAmount) external notPaused {
        require(to != address(0), "zero recipient");
        require(eTokenAmount > 0, "zero transfer");
        require(positions[msg.sender].eTokens >= eTokenAmount, "MockEuler: insufficient eTokens");
        positions[msg.sender].eTokens -= eTokenAmount;
        positions[to].eTokens          += eTokenAmount;
        emit Transfer(msg.sender, to, eTokenAmount);
    }

    function totalBorrows() external view override returns (uint256) { return _totalBorrows; }
    function totalReserves() external view override returns (uint256) { return _totalReserves; }
    function paused() external view override returns (bool) { return _paused; }

    function getAccountLiquidity(address account)
        external view override
        returns (uint256 collateralValue, uint256 liabilityValue)
    {
        return _accountLiquidity(account);
    }

    function pause() external override {
        _paused = true;
        emit Paused();
    }

    // Test helper for direct verification of the donation→liquidation flow.
    // The Trap itself uses getAccountLiquidity(account) per discovered address,
    // not this aggregator.
    function getTotalBadDebt(address[] calldata accounts)
        external view
        returns (uint256 badDebt)
    {
        for (uint256 i; i < accounts.length; i++) {
            (uint256 col, uint256 liab) = _accountLiquidity(accounts[i]);
            if (liab > col) { unchecked { badDebt += liab - col; } }
        }
    }

    function _accountLiquidity(address account)
        internal view
        returns (uint256 collateralValue, uint256 liabilityValue)
    {
        collateralValue = positions[account].eTokens * COLLATERAL_FACTOR_BPS / BPS;
        liabilityValue  = positions[account].dTokens;
    }
}
