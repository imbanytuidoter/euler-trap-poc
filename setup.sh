#!/usr/bin/env bash
set -e

echo "Installing forge-std..."
forge install foundry-rs/forge-std

echo "Building..."
forge build

echo "Running tests..."
forge test -vvv
