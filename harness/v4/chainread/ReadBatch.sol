// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Chain-read harness helper (docs/v4/CHAINREAD.md). NOT part of PQ-Identity v4:
// - it lives under harness/v4/chainread/, never under onchain/contracts/v4/;
// - packages/v4 never imports, deploys or calls it;
// - harness/v4/chainread deploys it on a local test chain (Anvil or the local Besu QBFT
//   network) only, from a fresh funded role account, after the v4 registries are set up.
// It runs the multicall client variant ("variant, not shipped"): several eth_call reads of the
// v4 registries in one eth_call. It is stateless and view-only (staticcall), so it can change
// nothing on chain. eth_getLogs cannot be aggregated inside the EVM, so it covers eth_call only.
contract ChainReadBatch {
    struct Call {
        address target;
        bytes data;
    }

    struct Result {
        bool ok;
        bytes data;
    }

    /// One staticcall per entry, in order. A failed call is reported (ok = false, data = the
    /// revert data) and does not stop the others; the client then re-sends that call alone.
    function aggregate(Call[] calldata calls) external view returns (uint256 blockNumber, Result[] memory results) {
        blockNumber = block.number;
        results = new Result[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].target.staticcall(calls[i].data);
            results[i] = Result(ok, ret);
        }
    }
}
