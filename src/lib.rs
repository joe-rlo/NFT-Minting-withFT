use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, near_bindgen, AccountId, PanicOnDefault, Promise, 
    BorshStorageKey, NearToken
};
use std::collections::HashMap;
use near_sdk::env::log_str;
use near_sdk::serde_json::json;
use near_sdk::serde_json;
use near_sdk::{PromiseOrValue};
use near_sdk::ext_contract;
use near_contract_standards::non_fungible_token::metadata::{
    NFTContractMetadata, TokenMetadata, NFT_METADATA_SPEC,
};
use near_contract_standards::non_fungible_token::{Token, TokenId};
use near_contract_standards::non_fungible_token::NonFungibleToken;

#[ext_contract(ext_ft)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[derive(BorshSerialize, BorshStorageKey)]
pub enum StorageKey {
    TokensPerOwner { account_id_hash: Vec<u8> },
    TokenMetadata,
    TokenIds,
    PayoutWallets,
    RoyaltyWallets,
    TraitCounts,
    NonFungibleToken,
    TokenMetadataById,
    Enumeration,
    Approval,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct CollectionMetadata {
    pub name: String,
    pub description: String,
    pub traits: Vec<TraitDefinition>,
    pub image: String,
    pub external_url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TraitDefinition {
    pub trait_type: String,
    pub values: Vec<TraitValue>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TraitValue {
    pub value: String,
    pub weight: u8,
    pub display_type: Option<String>,
    pub max_value: Option<u32>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct NFTMetadata {
    pub spec: String,              // Required, essentially a version like "nft-1.0.0"
    pub name: String,              // Required, ex. "Mosaics"
    pub symbol: String,            // Required, ex. "MOSAIC"
    pub icon: Option<String>,      // Data URL
    pub base_uri: Option<String>,  // Centralized gateway known to have reliable access to decentralized storage assets referenced by `reference` or `media` URLs
    pub reference: String,         // URL to JSON with collection metadata
    pub reference_hash: Option<Base64VecU8>, // Base64-encoded sha256 hash of JSON from reference field
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TokenData {
    pub token_id: String,
    pub owner_id: String,
    pub metadata: TokenMetadata,
    pub approved_account_ids: Option<HashMap<AccountId, bool>>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct PayoutWallet {
    pub account_id: AccountId,
    pub share: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Payout {
    pub payout: HashMap<AccountId, U128>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct FtOnTransferArgs {
    pub number_of_tokens: Option<u64>,  // Optional, defaults to 1 if not specified
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    pub owner_id: AccountId,
    pub tokens: NonFungibleToken,
    pub tokens_per_owner: LookupMap<AccountId, UnorderedSet<String>>,
    pub token_metadata: UnorderedMap<String, TokenMetadata>,
    pub token_ids: UnorderedSet<String>,
    pub mint_price: U128,
    pub ft_token_id: AccountId,
    pub max_supply: u64,
    pub total_supply: u64,
    pub payout_wallets: Vec<PayoutWallet>,
    pub royalty_wallets: Vec<PayoutWallet>,
    pub total_royalty: u8,
    pub metadata: NFTMetadata,
    pub attribute_counts: LookupMap<String, HashMap<String, u32>>,
    pub premint_only: bool,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(
        owner_id: AccountId,
        metadata: NFTMetadata,
        ft_token_id: AccountId,
        mint_price: U128,
        max_supply: u64,
        payout_wallets: Vec<(AccountId, u8)>,
        royalty_wallets: Vec<(AccountId, u8)>,
        total_royalty: u8,
    ) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        assert!(metadata.reference.len() > 0, "Reference URL required");

        let this = Self {
            tokens: NonFungibleToken::new(
                StorageKey::NonFungibleToken,
                owner_id.clone(),
                Some(StorageKey::TokenMetadataById),
                Some(StorageKey::Enumeration),
                Some(StorageKey::Approval),
            ),
            owner_id: owner_id.clone(),
            tokens_per_owner: LookupMap::new(StorageKey::TokensPerOwner { 
                account_id_hash: Vec::new() 
            }),
            token_metadata: UnorderedMap::new(StorageKey::TokenMetadata),
            token_ids: UnorderedSet::new(StorageKey::TokenIds),
            mint_price,
            ft_token_id,
            max_supply,
            total_supply: 0,
            payout_wallets: payout_wallets
                .into_iter()
                .map(|(account_id, share)| PayoutWallet { account_id, share })
                .collect(),
            royalty_wallets: royalty_wallets
                .into_iter()
                .map(|(account_id, share)| PayoutWallet { account_id, share })
                .collect(),
            total_royalty,
            metadata,
            attribute_counts: LookupMap::new(StorageKey::TraitCounts),
            premint_only: true,
        };

        
         // Log contract initialization
        let init_log = json!({
            "standard": "nep171",
            "version": "1.1.0",
            "event": "init",
            "data": {
                "owner_id": owner_id.to_string()
            }
        });
        log_str(&format!("EVENT_JSON:{}", init_log.to_string()));

        this
    }

    #[payable]
    pub fn mint_many(&mut self, _number_of_tokens: u64) -> Vec<TokenData> {
        // Implementation
        unimplemented!("Please use FT transfer to mint tokens");
    }

    fn get_next_token_id(&self) -> String {
        let mut next_id = 0;
        
        // Keep incrementing until we find an unminted ID
        while self.token_ids.contains(&next_id.to_string()) {
            next_id += 1;
            assert!(
                next_id < self.max_supply,
                "No more tokens available to mint"
            );
        }
        
        next_id.to_string()
    }

    fn internal_mint_many(
        &mut self,
        receiver_id: &AccountId,
        number_of_tokens: u64,
    ) -> Vec<TokenData> {
        assert!(
            self.total_supply + number_of_tokens <= self.max_supply,
            "Would exceed max supply"
        );

        let mut tokens_set = self.tokens_per_owner
            .get(receiver_id)
            .unwrap_or_else(|| {
                UnorderedSet::new(
                    StorageKey::TokensPerOwner { 
                        account_id_hash: env::sha256(receiver_id.as_bytes())
                    }
                )
            });

        let mut minted_tokens = Vec::with_capacity(number_of_tokens as usize);

        for _ in 0..number_of_tokens {
            let token_id = self.get_next_token_id();
            
            // Create metadata for this token
            let metadata = TokenMetadata {
                title: Some(format!("{} #{}", self.metadata.name, token_id)),
                description: Some(format!("Token {} from collection {}", token_id, self.metadata.name)),
                media: self.metadata.base_uri.clone().map(|uri| format!("{}/{}.png", uri, token_id)),
                media_hash: None,
                copies: Some(1),
                issued_at: Some(env::block_timestamp().to_string()),
                expires_at: None,
                starts_at: None,
                updated_at: None,
                extra: None,
                reference: Some(format!("{}/{}.json", self.metadata.reference, token_id)),
                reference_hash: None,
            };

            // Update the core NFT data structure
            self.tokens.internal_mint_with_refund(
                token_id.clone(),
                receiver_id.clone(),
                Some(metadata.clone()),
                None,
            );

            // Store token data in custom storage
            tokens_set.insert(&token_id);
            self.token_metadata.insert(&token_id, &metadata);
            self.token_ids.insert(&token_id);
            self.total_supply += 1;

            minted_tokens.push(TokenData {
                token_id: token_id.clone(),
                owner_id: receiver_id.to_string(),
                metadata,
                approved_account_ids: None,
            });
        }

        // Save the updated token set for this owner
        self.tokens_per_owner.insert(receiver_id, &tokens_set);

        minted_tokens
    }

    // Single implementation of distribute_payment
    fn distribute_payment(&mut self, amount: U128) {
        let mut remaining_amount = amount.0;
        let mut promise = Promise::new(self.ft_token_id.clone()); // Start with the FT contract as the initial promise
        
        for wallet in &self.payout_wallets {
            let wallet_share = (remaining_amount as f64 * (wallet.share as f64 / 100.0)) as u128;
            if wallet_share > 0 {
                promise = promise.then(
                    ext_ft::ext(self.ft_token_id.clone())
                        .with_attached_deposit(NearToken::from_yoctonear(1))
                        .ft_transfer(
                            wallet.account_id.clone(),
                            U128(wallet_share),
                            None,
                        )
                );
                remaining_amount -= wallet_share;
            }
        }

        // Send any dust to the first wallet
        if remaining_amount > 0 && !self.payout_wallets.is_empty() {
            promise = promise.then(
                ext_ft::ext(self.ft_token_id.clone())
                    .with_attached_deposit(NearToken::from_yoctonear(1))
                    .ft_transfer(
                        self.payout_wallets[0].account_id.clone(),
                        U128(remaining_amount),
                        None,
                    )
            );
        }
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        assert!(
            !self.premint_only,
            "Minting is currently restricted to premint only"
        );

        let args: FtOnTransferArgs = serde_json::from_str(&msg)
            .unwrap_or(FtOnTransferArgs { number_of_tokens: Some(1) });
        
        let number_of_tokens = args.number_of_tokens.unwrap_or(1);
        let required_amount = U128(self.mint_price.0.checked_mul(number_of_tokens as u128)
            .expect("Multiplication overflow"));
        
        assert!(
            amount.0 >= required_amount.0,
            "Insufficient FT tokens sent for minting"
        );

        let minted_tokens = self.internal_mint_many(
            &sender_id,
            number_of_tokens
        );

        // Log the standard NEP-171 mint event
        let nft_mint_log = json!({
            "standard": "nep171",
            "version": "1.1.0",
            "event": "nft_mint",
            "data": [{
                "owner_id": sender_id,
                "token_ids": minted_tokens.iter().map(|t| t.token_id.clone()).collect::<Vec<_>>(),
            }]
        });
        log_str(&format!("EVENT_JSON:{}", nft_mint_log.to_string()));

        // Log detailed metadata event
        let metadata_log = json!({
            "receiver_id": sender_id,
            "tokens": minted_tokens.iter().map(|token| {
                json!({
                    "token_id": token.token_id,
                    "receiver_id": sender_id,
                    "token_metadata": token.metadata
                })
            }).collect::<Vec<_>>()
        });
        log_str(&format!("METADATA_JSON:{}", metadata_log.to_string()));

        // Distribute the payment
        self.distribute_payment(required_amount);

        // Return unused tokens
        PromiseOrValue::Value(U128(amount.0 - required_amount.0))
    }

    // View methods
    pub fn nft_metadata(&self) -> NFTMetadata {
        self.metadata.clone()
    }

    pub fn nft_token(&self, token_id: TokenId) -> Option<Token> {
        if let Some(owner_id) = self.tokens.owner_by_id.get(&token_id) {
            let metadata = self.token_metadata.get(&token_id);
            
            Some(Token {
                token_id,
                owner_id,
                metadata,
                approved_account_ids: Some(HashMap::new()),
            })
        } else {
            None
        }
    }

    // NEP-199 interface for royalty distribution on secondary sales
    pub fn nft_payout(&self, token_id: String, balance: U128, max_len_payout: u32) -> Payout {
        let mut payout = HashMap::new();
        let balance_u128 = balance.0;

        // Calculate royalty amount
        let royalty_amount = (balance_u128 as f64 * (self.total_royalty as f64 / 100.0)) as u128;
        
        // Distribute royalties according to shares
        for wallet in &self.royalty_wallets {
            let wallet_share = (royalty_amount as f64 * (wallet.share as f64 / 100.0)) as u128;
            payout.insert(wallet.account_id.clone(), U128(wallet_share));
        }

        // Remaining amount goes to seller
        let seller_amount = balance_u128 - royalty_amount;
        let seller_id = self.tokens_per_owner
            .get(&env::predecessor_account_id())
            .expect("No token owner");
            
        // Verify token ownership
        assert!(
            seller_id.contains(&token_id),
            "Token does not belong to seller"
        );
            
        payout.insert(env::predecessor_account_id(), U128(seller_amount));

        assert!(
            payout.len() <= max_len_payout as usize,
            "Market cannot payout to that many receivers"
        );

        Payout { payout }
    }

    // Admin methods
    #[payable]
    pub fn update_mint_price(&mut self, price: U128) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update price"
        );
        self.mint_price = price;
    }

    #[payable]
    pub fn update_payout_wallets(&mut self, payout_wallets: Vec<(AccountId, u8)>) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update payout wallets"
        );
        
        let total_share: u8 = payout_wallets.iter().map(|(_, share)| share).sum();
        assert_eq!(total_share, 100, "Payout shares must total 100%");

        self.payout_wallets = payout_wallets
            .into_iter()
            .map(|(account_id, share)| PayoutWallet { account_id, share })
            .collect();
    }

    #[payable]
    pub fn update_royalty_wallets(&mut self, royalty_wallets: Vec<(AccountId, u8)>) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update royalty wallets"
        );
        
        let total_share: u8 = royalty_wallets.iter().map(|(_, share)| share).sum();
        assert_eq!(total_share, 100, "Royalty shares must total 100%");

        self.royalty_wallets = royalty_wallets
            .into_iter()
            .map(|(account_id, share)| PayoutWallet { account_id, share })
            .collect();
    }

    #[payable]
    pub fn update_total_royalty(&mut self, total_royalty: u8) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update royalty percentage"
        );
        assert!(total_royalty <= 100, "Royalty must be between 0 and 100");
        self.total_royalty = total_royalty;
    }

    // View methods
    pub fn get_token_metadata(&self, token_id: String) -> Option<TokenMetadata> {
        self.token_metadata.get(&token_id)
    }

    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    pub fn tokens_per_owner(&self, account_id: AccountId) -> Vec<String> {
        self.tokens_per_owner
            .get(&account_id)
            .map(|tokens| tokens.to_vec())
            .unwrap_or_default()
    }

    pub fn get_payout_wallets(&self) -> Vec<PayoutWallet> {
        self.payout_wallets.clone()
    }

    pub fn get_royalty_wallets(&self) -> Vec<PayoutWallet> {
        self.royalty_wallets.clone()
    }

    pub fn get_total_royalty(&self) -> u8 {
        self.total_royalty
    }

    /// Returns how many tokens are still available to mint
    pub fn get_remaining_supply(&self) -> u64 {
        self.max_supply - self.total_supply
    }

    /// Returns both max supply and current total supply
    pub fn get_supply_stats(&self) -> (u64, u64) {
        (self.max_supply, self.total_supply)
    }

    /// Allows contract owner to premint specific token IDs
    #[payable]
    pub fn premint(&mut self, token_id: String, receiver_id: AccountId) -> TokenData {
        // Only owner can premint
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can premint tokens"
        );

        // Check if token_id is valid number and within max supply
        let token_num = token_id.parse::<u64>()
            .expect("Token ID must be a number");
        assert!(
            token_num <= self.max_supply,
            "Token ID exceeds max supply"
        );

        // Ensure token hasn't been minted already
        assert!(
            !self.token_ids.contains(&token_id),
            "Token ID already minted"
        );

        // Get or create the tokens set for this receiver
        let mut tokens_set = self.tokens_per_owner
            .get(&receiver_id)
            .unwrap_or_else(|| {
                UnorderedSet::new(
                    StorageKey::TokensPerOwner { 
                        account_id_hash: env::sha256(receiver_id.as_bytes())
                    }
                )
            });

        // Create metadata for this token
        let metadata = TokenMetadata {
            title: Some(format!("{} #{}", self.metadata.name, token_id)),
            description: Some(format!("Token {} from collection {}", token_id, self.metadata.name)),
            media: self.metadata.base_uri.clone().map(|uri| format!("{}/{}.png", uri, token_id)),
            media_hash: None,
            copies: Some(1),
            issued_at: Some(env::block_timestamp().to_string()),
            expires_at: None,
            starts_at: None,
            updated_at: None,
            extra: None,
            reference: Some(format!("{}/{}.json", self.metadata.reference, token_id)),
            reference_hash: None,
        };

        // Update the core NFT data structure
        self.tokens.internal_mint_with_refund(
            token_id.clone(),
            receiver_id.clone(),
            Some(metadata.clone()),
            None,
        );

        // Store token data
        tokens_set.insert(&token_id);
        self.token_metadata.insert(&token_id, &metadata);
        self.token_ids.insert(&token_id);
        self.total_supply += 1;

        // Save the updated token set for this owner
        self.tokens_per_owner.insert(&receiver_id, &tokens_set);

        // Log the mint event
        let nft_mint_log = json!({
            "standard": "nep171",
            "version": "1.1.0",
            "event": "nft_mint",
            "data": [{
                "owner_id": receiver_id,
                "token_ids": [token_id.clone()],
            }]
        });
        log_str(&format!("EVENT_JSON:{}", nft_mint_log.to_string()));

        TokenData {
            token_id: token_id.clone(),
            owner_id: receiver_id.to_string(),
            metadata,
            approved_account_ids: None,
        }
    }

    /// Allows contract owner to update the collection metadata
    #[payable]
    pub fn update_metadata(
        &mut self,
        name: Option<String>,
        symbol: Option<String>,
        icon: Option<String>,
        base_uri: Option<String>,
        reference: Option<String>,
    ) {
        // Only owner can update metadata
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update metadata"
        );

        // Update only the provided fields
        if let Some(name) = name {
            self.metadata.name = name;
        }
        if let Some(symbol) = symbol {
            self.metadata.symbol = symbol;
        }
        if let Some(icon) = icon {
            self.metadata.icon = Some(icon);
        }
        if let Some(base_uri) = base_uri {
            self.metadata.base_uri = Some(base_uri);
        }
        if let Some(reference) = reference {
            assert!(reference.len() > 0, "Reference URL cannot be empty");
            self.metadata.reference = reference;
        }
    }

    /// Allows contract owner to update individual token metadata
    #[payable]
    pub fn update_token_metadata(
        &mut self,
        token_id: String,
        title: Option<String>,
        description: Option<String>,
        media: Option<String>,
        media_hash: Option<Base64VecU8>,
        copies: Option<u64>,
        extra: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
    ) -> TokenMetadata {
        // Only owner can update token metadata
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update token metadata"
        );

        // Ensure token exists
        let mut metadata = self.token_metadata.get(&token_id)
            .expect("Token not found");

        // Update only the provided fields
        if let Some(title) = title {
            metadata.title = Some(title);
        }
        if let Some(description) = description {
            metadata.description = Some(description);
        }
        if let Some(media) = media {
            metadata.media = Some(media);
        }
        if let Some(media_hash) = media_hash {
            metadata.media_hash = Some(media_hash);
        }
        if let Some(copies) = copies {
            metadata.copies = Some(copies);
        }
        if let Some(extra) = extra {
            metadata.extra = Some(extra);
        }
        if let Some(reference) = reference {
            metadata.reference = Some(reference);
        }
        if let Some(reference_hash) = reference_hash {
            metadata.reference_hash = Some(reference_hash);
        }

        // Update the timestamp
        metadata.updated_at = Some(env::block_timestamp().to_string());

        // Save the updated metadata
        self.token_metadata.insert(&token_id, &metadata);

        metadata
    }

    pub fn nft_total_supply(&self) -> U128 {
        U128(self.total_supply as u128)
    }

    pub fn nft_tokens(&self, from_index: Option<U128>, limit: Option<u64>) -> Vec<Token> {
        let start = u128::from(from_index.unwrap_or(U128(0)));
        let limit = limit.unwrap_or(50) as usize;
        
        self.token_ids.iter()
            .skip(start as usize)
            .take(limit)
            .filter_map(|token_id| self.nft_token(token_id))
            .collect()
    }

    pub fn nft_supply_for_owner(&self, account_id: AccountId) -> U128 {
        self.tokens_per_owner.get(&account_id)
            .map(|tokens| U128(tokens.len() as u128))
            .unwrap_or(U128(0))
    }


    /// Get all tokens owned by an account with optional pagination and filtering
    pub fn get_tokens_for_owner(
        &self,
        account_id: AccountId,
        from_index: Option<U128>,
        limit: Option<u64>,
        sort: Option<String>, // "asc" or "desc"
    ) -> Vec<Token> {
        let tokens = if let Some(token_set) = self.tokens_per_owner.get(&account_id) {
            let mut tokens: Vec<_> = token_set.iter().collect();
            
            // Apply sorting if specified
            if let Some(sort_order) = sort {
                match sort_order.as_str() {
                    "asc" => tokens.sort(),
                    "desc" => tokens.sort_by(|a, b| b.cmp(a)),
                    _ => (), // Invalid sort order, leave unsorted
                }
            }

            // Apply pagination
            let start = u128::from(from_index.unwrap_or(U128(0))) as usize;
            let limit = limit.unwrap_or(50) as usize;

            tokens.iter()
                .skip(start)
                .take(limit)
                .filter_map(|token_id| self.nft_token(token_id.clone()))
                .collect()
        } else {
            vec![]
        };

        tokens
    }


    /// Check if an account owns specific tokens
    pub fn check_token_ownership(&self, account_id: AccountId, token_ids: Vec<String>) -> Vec<bool> {
        let owned_tokens = self.tokens_per_owner.get(&account_id)
            .unwrap_or_else(|| UnorderedSet::new(StorageKey::TokensPerOwner {
                account_id_hash: env::sha256(account_id.as_bytes())
            }));

        token_ids.iter()
            .map(|token_id| owned_tokens.contains(token_id))
            .collect()
    }

    /// Required for NEP-171 transfers
    #[payable]
    pub fn nft_transfer(
        &mut self,
        receiver_id: AccountId,
        token_id: TokenId,
        approval_id: Option<u64>,
        memo: Option<String>,
    ) {
        Self::assert_one_yocto();
        let sender_id = env::predecessor_account_id();
        
        // Get tokens for sender
        let sender_tokens = self.tokens_per_owner.get(&sender_id)
            .expect("Sender has no tokens");
        
        // Verify sender owns the token
        assert!(
            sender_tokens.contains(&token_id),
            "Sender does not own this token"
        );

        // Remove token from sender
        let mut sender_tokens = self.tokens_per_owner.get(&sender_id).unwrap();
        sender_tokens.remove(&token_id);
        
        // Update or remove sender's token set
        if sender_tokens.is_empty() {
            self.tokens_per_owner.remove(&sender_id);
        } else {
            self.tokens_per_owner.insert(&sender_id, &sender_tokens);
        }

        // Add token to receiver
        let mut receiver_tokens = self.tokens_per_owner
            .get(&receiver_id)
            .unwrap_or_else(|| {
                UnorderedSet::new(
                    StorageKey::TokensPerOwner {
                        account_id_hash: env::sha256(receiver_id.as_bytes())
                    }
                )
            });
        receiver_tokens.insert(&token_id);
        self.tokens_per_owner.insert(&receiver_id, &receiver_tokens);

        // Log the transfer
        if let Some(ref memo) = memo {
            log_str(&format!("Memo: {}", memo));
        }

        let nft_transfer_log = json!({
            "standard": "nep171",
            "version": "1.1.0",
            "event": "nft_transfer",
            "data": [{
                "authorized_id": approval_id.map(|id| id.to_string()),
                "old_owner_id": sender_id,
                "new_owner_id": receiver_id,
                "token_ids": [token_id],
                "memo": memo,
            }]
        });
        log_str(&format!("EVENT_JSON:{}", nft_transfer_log.to_string()));
    }

    /// Helper assert for 1 yoctoNEAR attachments
    fn assert_one_yocto() {
        assert_eq!(
            env::attached_deposit(),
            NearToken::from_yoctonear(1),
            "Requires attached deposit of exactly 1 yoctoNEAR"
        );
    }

    #[payable]
    pub fn set_premint_only(&mut self, enabled: bool) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can toggle premint-only mode"
        );
        self.premint_only = enabled;
    }

    pub fn is_premint_only(&self) -> bool {
        self.premint_only
    }
}
