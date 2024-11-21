# NEAR NFT Contract With FT Minting & Distribution

A feature-rich NFT smart contract built for the NEAR Protocol that supports minting with FT tokens, royalties, and configurable payment distribution.

## Features

- 🎨 NFT minting with automatic metadata generation
- 💰 Configurable mint price in FT tokens
- 🔢 Maximum supply limit
- 💸 Primary sale payment distribution
- 👥 Secondary sale royalties
- 🔄 Updatable parameters by owner
- 📊 Comprehensive metadata support
- 🏷️ Token trait tracking

## Contract Structure

The contract implements the following key components:
- NFT metadata following NEP-177
- Token ownership tracking
- FT payment distribution system
- Royalty management (NEP-199)

## Initialization

Deploy and initialize the contract with the following parameters:
```bash
near deploy --wasmFile nft_contract.wasm --accountId YOUR_CONTRACT_ID
near call YOUR_CONTRACT_ID new '{
    "owner_id": "owner.near",
    "metadata": {
        "spec": "nft-1.0.0",
        "name": "My NFT Collection",
        "symbol": "MNFT",
        "icon": "data:image/svg+xml,...",
        "base_uri": "https://api.mynft.com/assets/",
        "reference": "https://api.mynft.com/metadata/collection.json",
        "reference_hash": null
    },
    "ft_token_id": "token.near",
    "mint_price": "1000000000000000000000000",
    "max_supply": 1000,
    "payout_wallets": [
        ["treasury.near", 70],
        ["developer.near", 30]
    ],
    "royalty_wallets": [
        ["creator.near", 80],
        ["team.near", 20]
    ],
    "total_royalty": 10
}' --accountId OWNER_ACCOUNT_ID
```

## Minting

To mint NFTs, you need to:
1. Approve the NFT contract to use your FT tokens
2. Call the FT contract to transfer tokens and mint NFTs

```bash
# First approve the NFT contract to use your tokens
near call $FT_TOKEN_ID ft_approve '{
    "account_id": "'$NFT_CONTRACT_ID'",
    "amount": "1000000000000000000000000"
}' --accountId BUYER_ID --deposit 0.0001

# Then mint NFTs (example mints 3 tokens)
near call $FT_TOKEN_ID ft_transfer_call '{
    "receiver_id": "'$NFT_CONTRACT_ID'",
    "amount": "3000000000000000000000000",
    "msg": "{\"number_of_tokens\": 3}"
}' --accountId BUYER_ID --deposit 0.000000000000000000000001
```

## Supply Information
```bash
# Get remaining supply
near view YOUR_CONTRACT_ID get_remaining_supply

# Get both max supply and current total supply
near view YOUR_CONTRACT_ID get_supply_stats

# Get total supply
near view YOUR_CONTRACT_ID total_supply
```

## Token Information
```bash
# Get token metadata
near view YOUR_CONTRACT_ID get_token_metadata '{"token_id": "1"}'

# Get tokens owned by account
near view YOUR_CONTRACT_ID tokens_per_owner '{"account_id": "owner.near"}'
```

## Configuration

### View Current Settings
```bash
# Get current mint price (in FT tokens)
near view YOUR_CONTRACT_ID get_mint_price

# Get payout configuration
near view YOUR_CONTRACT_ID get_payout_wallets
near view YOUR_CONTRACT_ID get_royalty_wallets
near view YOUR_CONTRACT_ID get_total_royalty
```

### Update Settings (Owner Only)
```bash
# Update mint price
near call YOUR_CONTRACT_ID update_mint_price '{"price": "2000000000000000000000000"}' \
    --accountId OWNER_ACCOUNT_ID

# Update payout wallets
near call YOUR_CONTRACT_ID update_payout_wallets '{
    "payout_wallets": [
        ["treasury.near", 60],
        ["developer.near", 40]
    ]
}' --accountId OWNER_ACCOUNT_ID

# Update royalty wallets
near call YOUR_CONTRACT_ID update_royalty_wallets '{
    "royalty_wallets": [
        ["creator.near", 70],
        ["team.near", 30]
    ]
}' --accountId OWNER_ACCOUNT_ID

# Update total royalty
near call YOUR_CONTRACT_ID update_total_royalty '{"total_royalty": 5}' \
    --accountId OWNER_ACCOUNT_ID
```

## Payment Distribution

### Primary Sales
When an NFT is minted, the FT payment is automatically distributed according to the `payout_wallets` configuration. For example, with the default configuration:
- 70% goes to treasury.near
- 30% goes to developer.near

### Secondary Sales
When an NFT is sold on a marketplace, the contract provides royalty information through the `nft_payout` method following NEP-199. With the default configuration:
- 10% of the sale price is distributed as royalties:
  - 80% of royalties (8% of sale) goes to creator.near
  - 20% of royalties (2% of sale) goes to team.near
- 90% goes to the seller

## Important Notes

1. All FT values are in the token's smallest unit (check your FT's decimals)
2. Payout and royalty shares must each total 100%
3. Total royalty must be between 0 and 100
4. Account IDs must be valid NEAR accounts
5. The contract owner can update prices and payment configurations
6. Token IDs are sequential starting from 1
7. Each token's metadata URL is constructed using the collection's base_uri
8. The FT contract must be specified during initialization
9. Users must approve the NFT contract to use their FT tokens

