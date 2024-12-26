use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, near_bindgen, AccountId, PanicOnDefault, Promise, 
    BorshStorageKey, NearToken, Gas, PromiseResult, PromiseOrValue
};
use std::collections::HashMap;
use near_sdk::env::log_str;
use near_sdk::serde_json::json;
use near_sdk::serde_json;
use near_sdk::ext_contract;
use near_contract_standards::non_fungible_token::metadata::{
    NFTContractMetadata, TokenMetadata, NFT_METADATA_SPEC,
};

use near_contract_standards::non_fungible_token::{Token, TokenId};
use near_contract_standards::non_fungible_token::NonFungibleToken;
use near_sdk::assert_one_yocto;
use near_contract_standards::fungible_token::Balance;

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
    pub ft_decimals: u8,
    pub max_supply: u64,
    pub total_supply: u64,
    pub payout_wallets: Vec<PayoutWallet>,
    pub royalty_wallets: Vec<PayoutWallet>,
    pub total_royalty: u8,
    pub metadata: NFTMetadata,
    pub attribute_counts: LookupMap<String, HashMap<String, u32>>,
    pub premint_only: bool,
}

#[ext_contract(ext_self)]
pub trait ExtSelf {
    fn on_ft_transfer_complete(
        &mut self,
        sender_id: AccountId,
        number_of_tokens: u64,
    ) -> Vec<TokenData>;
}

#[near_bindgen]
impl Contract {
    fn to_token_units(whole_tokens: u128, decimals: u8) -> U128 {
        U128(whole_tokens * 10u128.pow(decimals as u32))
    }

    #[init]
    pub fn new(
        owner_id: AccountId,
        metadata: NFTMetadata,
        ft_token_id: AccountId,
        ft_decimals: u8,
        mint_price: String,  // This should be the FULL price including decimals
        max_supply: u64,
        payout_wallets: Vec<PayoutWallet>,
        royalty_wallets: Vec<PayoutWallet>,
        total_royalty: u8,
    ) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        
        // Parse the full price directly (no multiplication needed)
        let mint_price_u128 = mint_price.parse::<u128>()
            .expect("Invalid mint price format");

        log_str(&format!(
            "Initializing contract with price {} ({} decimals)",
            mint_price_u128, ft_decimals
        ));

        Self {
            owner_id: owner_id.clone(),
            tokens: NonFungibleToken::new(
                StorageKey::NonFungibleToken,
                owner_id.clone(),
                Some(StorageKey::TokenMetadataById),
                Some(StorageKey::Enumeration),
                Some(StorageKey::Approval),
            ),
            tokens_per_owner: LookupMap::new(StorageKey::TokensPerOwner {
                account_id_hash: env::sha256(owner_id.as_bytes()),
            }),
            token_metadata: UnorderedMap::new(StorageKey::TokenMetadata),
            token_ids: UnorderedSet::new(StorageKey::TokenIds),
            metadata,
            mint_price: U128(mint_price_u128),  // Store the full price directly
            ft_token_id,
            ft_decimals,
            max_supply,
            total_supply: 0,
            payout_wallets,
            royalty_wallets,
            total_royalty,
            premint_only: false,
            attribute_counts: LookupMap::new(StorageKey::TraitCounts),
        }
    }

    #[payable]
    pub fn mint_many(&mut self, _number_of_tokens: u64) -> Vec<TokenData> {
        // Implementation
        unimplemented!("Please use FT transfer to mint tokens");
    }

    fn get_next_token_id(&self) -> String {
        let mut next_id = 0;
        while next_id < self.max_supply {
            if !self.token_ids.contains(&next_id.to_string()) {
                return next_id.to_string();
            }
            next_id += 1;
        }
        env::panic_str("No more tokens available");
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

        // Pre-allocate vectors and get references once
        let mut minted_tokens = Vec::with_capacity(number_of_tokens as usize);
        let base_uri = self.metadata.base_uri.as_ref();
        let reference = &self.metadata.reference;

        // Get or create tokens set once
        let mut tokens_set = self.tokens_per_owner
            .get(receiver_id)
            .unwrap_or_else(|| {
                UnorderedSet::new(
                    StorageKey::TokensPerOwner { 
                        account_id_hash: env::sha256(receiver_id.as_bytes())
                    }
                )
            });

        for _ in 0..number_of_tokens {
            let token_id = self.get_next_token_id();
            
            // Minimal metadata
            let metadata = TokenMetadata {
                title: Some(format!("{} #{}", self.metadata.name, token_id)),
                description: None,
                media: base_uri.map(|uri| format!("{}/{}.png", uri, token_id)),
                media_hash: None,
                copies: Some(1),
                issued_at: None,
                expires_at: None,
                starts_at: None,
                updated_at: None,
                extra: None,
                reference: Some(format!("{}/{}.json", reference, token_id)),
                reference_hash: None,
            };

            // Batch operations
            self.tokens.internal_mint_with_refund(
                token_id.clone(),
                receiver_id.clone(),
                Some(metadata.clone()),
                None,
            );

            tokens_set.insert(&token_id);
            self.token_metadata.insert(&token_id, &metadata);
            self.token_ids.insert(&token_id);
            self.total_supply += 1;

            minted_tokens.push(TokenData {
                token_id,
                owner_id: receiver_id.to_string(),
                metadata,
                approved_account_ids: None,
            });
        }

        // Single storage write for tokens_set
        self.tokens_per_owner.insert(receiver_id, &tokens_set);

        minted_tokens
    }

    // Single implementation of distribute_payment
    fn distribute_payment(&mut self, amount: U128) {
        let total_amount = amount.0;
        let mut remaining_amount = total_amount;
        let mut promise = Promise::new(self.ft_token_id.clone());
        
        // Process all wallets except the last one
        for wallet in self.payout_wallets.iter().take(self.payout_wallets.len() - 1) {
            // Convert share to u128 before multiplication to avoid overflow
            let share_u128 = u128::from(wallet.share);
            let wallet_amount = (total_amount * share_u128) / 100u128;
            remaining_amount -= wallet_amount;

            if wallet_amount > 0 {
                promise = promise.then(
                    Promise::new(self.ft_token_id.clone())
                        .function_call(
                            "ft_transfer".to_string(),
                            json!({
                                "receiver_id": wallet.account_id,
                                "amount": U128(wallet_amount),
                                "memo": Some(format!("Payout share: {}%", wallet.share))
                            }).to_string().into_bytes(),
                            NearToken::from_yoctonear(1),
                            Gas::from_tgas(5)
                        )
                );
            }
        }

        // Send remaining amount to last wallet
        if let Some(last_wallet) = self.payout_wallets.last() {
            if remaining_amount > 0 {
                promise = promise.then(
                    Promise::new(self.ft_token_id.clone())
                        .function_call(
                            "ft_transfer".to_string(),
                            json!({
                                "receiver_id": last_wallet.account_id,
                                "amount": U128(remaining_amount),
                                "memo": Some(format!("Payout share: {}% (including dust)", last_wallet.share))
                            }).to_string().into_bytes(),
                            NearToken::from_yoctonear(1),
                            Gas::from_tgas(5)
                        )
                );
            }
        }
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        if self.premint_only {
            return PromiseOrValue::Value(amount);
        }

        // Simple number parsing
        let number_of_tokens = msg.parse::<u64>().unwrap_or(1);
        let required_amount = self.mint_price.0.saturating_mul(number_of_tokens as u128);
        
        if amount.0 < required_amount {
            return PromiseOrValue::Value(amount);
        }

        // Direct minting
        let minted_tokens = self.internal_mint_many(&sender_id, number_of_tokens);
        let token_ids: Vec<String> = minted_tokens.iter()
            .map(|t| t.token_id.clone())
            .collect();
        
        // Single event log
        log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nep171\",\"version\":\"1.0.0\",\"event\":\"nft_mint\",\"data\":[{{\"owner_id\":\"{}\",\"token_ids\":{:?}}}]}}",
            sender_id,
            token_ids
        ));

        PromiseOrValue::Value(U128(amount.0 - required_amount))
    }

    #[private]
    pub fn on_ft_transfer_complete(
        &mut self,
        sender_id: AccountId,
        number_of_tokens: u64,
    ) -> Vec<TokenData> {
        // Verify the payment callbacks succeeded
        assert!(env::promise_results_count() > 0, "No promise results");
        
        // Check if all previous promises succeeded
        let mut all_promises_succeeded = true;
        for i in 0..env::promise_results_count() {
            match env::promise_result(i) {
                PromiseResult::Successful(_) => continue,
                _ => {
                    all_promises_succeeded = false;
                    break;
                }
            }
        }

        if !all_promises_succeeded {
            log_str("Payment distribution failed. Aborting mint.");
            return vec![];
        }

        // If we get here, all payments succeeded, so we can mint
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

        minted_tokens
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
    pub fn update_mint_price(&mut self, price: u8) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update price"
        );
        self.mint_price = Self::to_token_units(price as u128, self.ft_decimals);
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
        Self::assert_at_least_one_yocto();
        let sender_id = env::predecessor_account_id();
        
        // First verify ownership
        let owner_id = self.tokens.owner_by_id.get(&token_id)
            .expect("Token not found");

        assert_eq!(
            owner_id,
            sender_id,
            "Sender does not own this token"
        );

        // Update core NFT logic first
        self.tokens.internal_transfer(
            &sender_id,
            &receiver_id,
            &token_id,
            approval_id,
            memo.clone(),
        );

        // Now handle our custom token tracking
        // First verify the token exists and get its data
        let token = self.nft_token(token_id.clone())
            .expect("Token not found");

        // Get fresh copies of the token sets AFTER the core transfer
        let mut sender_tokens = self.tokens_per_owner 
            .get(&sender_id)
            .expect("Sender tokens not found in tokens_per_owner");  // Keep strict checking
        sender_tokens.remove(&token_id);
        
        let mut receiver_tokens = self.tokens_per_owner
            .get(&receiver_id)
            .unwrap_or_else(|| {
                UnorderedSet::new(
                    StorageKey::TokensPerOwner {
                        account_id_hash: env::sha256(receiver_id.as_bytes())
                    }
                )
            });
        
        // Update the token sets
        receiver_tokens.insert(&token_id);
        
        // Save the updated sets
        if sender_tokens.is_empty() {
            self.tokens_per_owner.remove(&sender_id);
        } else {
            self.tokens_per_owner.insert(&sender_id, &sender_tokens);
        }
        self.tokens_per_owner.insert(&receiver_id, &receiver_tokens);

        // Log the transfer in a single call
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
        log_str(&format!("EVENT_JSON:{}", nft_transfer_log));
    }

    /// Helper assert for 1 yoctoNEAR attachments
    fn assert_at_least_one_yocto() {
        assert!(
            env::attached_deposit() >= NearToken::from_yoctonear(1),
            "Requires attached deposit of at least 1 yoctoNEAR"
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

    // Add a function to update decimals if needed
    #[payable]
    pub fn update_ft_decimals(&mut self, decimals: u8) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can update token decimals"
        );
        self.ft_decimals = decimals;
    }

    #[payable]
    pub fn nft_approve(&mut self, token_id: TokenId, account_id: AccountId, msg: Option<String>) {
        // Assert at least one yocto for security
        assert_at_least_one_yocto();

        // Get the token owner
        let owner_id = self.tokens.owner_by_id.get(&token_id)
            .expect("Token not found");

        // Make sure that the person calling the function is the owner of the token
        assert_eq!(
            env::predecessor_account_id(),
            owner_id,
            "Predecessor must be token owner"
        );

        // Initialize approvals_by_id if it doesn't exist
        if self.tokens.approvals_by_id.is_none() {
            self.tokens.approvals_by_id = Some(LookupMap::new(StorageKey::Approval));
        }

        // Get or initialize the approvals map
        let mut approved_account_ids = self.tokens.approvals_by_id
            .as_ref()
            .unwrap()  // Safe now because we initialized it above
            .get(&token_id)
            .unwrap_or_else(HashMap::new);

        // Check if this is a new approval
        let is_new_approval = !approved_account_ids.contains_key(&account_id);

        // Generate approval_id
        let approval_id = env::block_height();  // Using block height ensures uniqueness
        
        // Add the approval
        approved_account_ids.insert(account_id.clone(), approval_id);
        
        // Update approvals
        self.tokens.approvals_by_id.as_mut().unwrap().insert(&token_id, &approved_account_ids);

        // Calculate storage used if this is a new approval
        let storage_used = if is_new_approval {
            Self::bytes_for_approved_account_id(&account_id)
        } else {
            0
        };

        // Refund excess storage deposit
        Self::refund_deposit(storage_used);

        // If msg is provided, initiate cross-contract call
        if let Some(msg) = msg {
            Promise::new(account_id)
                .function_call(
                    "nft_on_approve".to_string(),
                    json!({
                        "token_id": token_id,
                        "owner_id": owner_id,
                        "approval_id": approval_id,
                        "msg": msg,
                    })
                    .to_string()
                    .into_bytes(),
                    NearToken::from_yoctonear(0),
                    Gas::from_tgas(10)
                );
        }
    }

    // Add helper functions
    pub(crate) fn bytes_for_approved_account_id(account_id: &AccountId) -> u64 {
        // The extra 4 bytes are coming from Borsh serialization to store the length of the string
        account_id.as_str().len() as u64 + 4 + size_of::<u64>() as u64
    }

    fn refund_deposit(storage_used: u64) {
        let required_cost = env::storage_byte_cost().as_yoctonear() * storage_used as u128;
        let attached_deposit = env::attached_deposit().as_yoctonear();
        
        assert!(
            attached_deposit >= required_cost,
            "Must attach {} yoctoNEAR to cover storage",
            required_cost,
        );

        let refund = attached_deposit - required_cost;
        if refund > 1 {
            Promise::new(env::predecessor_account_id()).transfer(NearToken::from_yoctonear(refund));
        }
    }

    #[payable]
    pub fn nft_revoke(&mut self, token_id: TokenId, account_id: AccountId) {
        assert_at_least_one_yocto();

        let owner_id = self.tokens.owner_by_id.get(&token_id)
            .expect("Token not found");

        assert_eq!(
            env::predecessor_account_id(),
            owner_id,
            "Predecessor must be token owner"
        );

        // Get and update approvals
        if let Some(approvals_by_id) = &mut self.tokens.approvals_by_id {
            if let Some(mut approved_account_ids) = approvals_by_id.get(&token_id) {
                if approved_account_ids.remove(&account_id).is_some() {
                    approvals_by_id.insert(&token_id, &approved_account_ids);
                }
            }
        }
    }

    #[payable]
    pub fn nft_revoke_all(&mut self, token_id: TokenId) {
        assert_at_least_one_yocto();

        let owner_id = self.tokens.owner_by_id.get(&token_id)
            .expect("Token not found");

        assert_eq!(
            env::predecessor_account_id(),
            owner_id,
            "Predecessor must be token owner"
        );

        if let Some(approvals_by_id) = &mut self.tokens.approvals_by_id {
            approvals_by_id.remove(&token_id);
        }
    }

    pub fn nft_is_approved(
        &self,
        token_id: TokenId,
        approved_account_id: AccountId,
        approval_id: Option<u64>,
    ) -> bool {
        if let Some(approvals) = self.tokens.approvals_by_id.as_ref() {
            if let Some(approved_accounts) = approvals.get(&token_id) {
                if let Some(&actual_approval_id) = approved_accounts.get(&approved_account_id) {
                    approval_id.map_or(true, |id| actual_approval_id == id)
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }



    #[payable]
    pub fn rebuild_tokens_per_owner(&mut self, from_index: Option<u64>, limit: Option<u64>) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can rebuild tokens_per_owner"
        );

        let start = from_index.unwrap_or(0);
        let limit = limit.unwrap_or(50);

        // First collect all tokens and their owners in this batch
        let mut owner_tokens: std::collections::HashMap<AccountId, Vec<TokenId>> = std::collections::HashMap::new();
        
        // Process each token in range
        for token_id in start..(start + limit) {
            let token_id = token_id.to_string();
            
            // Get current owner from core NFT logic
            if let Some(current_owner) = self.tokens.owner_by_id.get(&token_id) {
                log_str(&format!("Found token {} owned by {}", token_id, current_owner));
                
                // Verify against nft_token for double-checking
                if let Some(token) = self.nft_token(token_id.clone()) {
                    assert_eq!(
                        current_owner,
                        token.owner_id,
                        "Owner mismatch for token {}: {} vs {}",
                        token_id,
                        current_owner,
                        token.owner_id
                    );
                    
                    // Add to our collection using verified owner
                    owner_tokens
                        .entry(current_owner.clone())
                        .or_insert_with(Vec::new)
                        .push(token_id);
                }
            }
        }

        // Now process each owner's tokens
        for (owner_id, new_tokens) in owner_tokens {
            log_str(&format!("Processing {} tokens for {}", new_tokens.len(), owner_id));
            
            // Create a temporary storage key
            let temp_key = StorageKey::TokensPerOwner {
                account_id_hash: env::sha256(format!("{}:{}", owner_id, env::block_timestamp()).as_bytes()),
            };
            
            // Create a new temporary set
            let mut temp_set = UnorderedSet::new(temp_key);
            
            // First add any existing tokens that are still owned by this account
            if let Some(existing_set) = self.tokens_per_owner.get(&owner_id) {
                log_str(&format!("Found existing set for {} with {} tokens", owner_id, existing_set.len()));
                for existing_token in existing_set.iter() {
                    // Only keep tokens still owned by this account
                    if let Some(current_owner) = self.tokens.owner_by_id.get(&existing_token) {
                        if current_owner == owner_id {
                            temp_set.insert(&existing_token);
                        }
                    }
                }
            }

            // Add all verified new tokens for this owner
            for token_id in new_tokens.iter() {
                log_str(&format!("Adding token {} to set for {}", token_id, owner_id));
                temp_set.insert(token_id);
            }
            
            let size_before_save = temp_set.len();
            log_str(&format!("Set size for {} before save: {}", owner_id, size_before_save));
            
            // Save the complete set or remove if empty
            if temp_set.is_empty() {
                self.tokens_per_owner.remove(&owner_id);
                log_str(&format!("Removed empty set for account: {}", owner_id));
            } else {
                self.tokens_per_owner.insert(&owner_id, &temp_set);
                
                // Verify the save
                if let Some(final_set) = self.tokens_per_owner.get(&owner_id) {
                    let final_tokens: Vec<_> = final_set.iter().collect();
                    log_str(&format!("Final set for {} contains {} tokens: {:?}", 
                        owner_id, final_set.len(), final_tokens));
                }
            }
        }
    }

    // Clean version of get_tokens_per_owner_count
    pub fn get_tokens_per_owner_count(&self, account_id: AccountId) -> u64 {
        if let Some(token_set) = self.tokens_per_owner.get(&account_id) {
            token_set.len() as u64
        } else {
            0
        }
    }

    // Clean version of nft_tokens_for_owner
    pub fn nft_tokens_for_owner(
        &self,
        account_id: AccountId,
        from_index: Option<U128>,
        limit: Option<u64>,
    ) -> Vec<Token> {
        let tokens = if let Some(token_set) = self.tokens_per_owner.get(&account_id) {
            let start = u128::from(from_index.unwrap_or(U128(0))) as usize;
            let limit = limit.unwrap_or(50) as usize;

            token_set.iter()
                .skip(start)
                .take(limit)
                .filter_map(|token_id| self.nft_token(token_id.clone()))
                .collect()
        } else {
            vec![]
        };

        tokens
    }

    #[payable]
    pub fn cleanup_storage(&mut self, account_index: Option<u64>) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can cleanup storage"
        );

        // Get initial storage usage
        let initial_storage = env::storage_usage();
        log_str(&format!("Initial storage usage: {} bytes", initial_storage));

        // Collect unique accounts (but only until we find the one we want)
        let mut accounts_to_check = Vec::new();
        let target_index = account_index.unwrap_or(0) as usize;
        
        'outer: for token_id in self.token_ids.iter() {
            if let Some(token) = self.nft_token(token_id) {
                if !accounts_to_check.contains(&token.owner_id) {
                    accounts_to_check.push(token.owner_id);
                    if accounts_to_check.len() > target_index {
                        break 'outer;
                    }
                }
            }
        }

        // Process only the target account if it exists
        if let Some(account_id) = accounts_to_check.get(target_index) {
            log_str(&format!("Processing account {}", account_id));
            
            if let Some(token_set) = self.tokens_per_owner.get(account_id) {
                if token_set.is_empty() {
                    log_str(&format!("Found empty set for account: {}", account_id));
                    self.tokens_per_owner.remove(account_id);
                    log_str(&format!("Removed empty set for account: {}", account_id));
                } else {
                    // Verify tokens actually exist
                    let mut valid_tokens = Vec::new();
                    for token_id in token_set.iter() {
                        if let Some(_token) = self.nft_token(token_id.clone()) {
                            valid_tokens.push(token_id);
                        } else {
                            log_str(&format!("Found invalid token {} for account {}", token_id, account_id));
                        }
                    }

                    // Convert lengths to same type for comparison
                    let set_len: usize = token_set.len().try_into().unwrap();
                    let valid_len = valid_tokens.len();

                    // If set needs cleanup
                    if valid_len < set_len {
                        log_str(&format!(
                            "Account {} has {} invalid tokens, rebuilding set",
                            account_id,
                            set_len - valid_len
                        ));

                        // Create new set with only valid tokens
                        let temp_key = StorageKey::TokensPerOwner {
                            account_id_hash: env::sha256(format!("{}:{}", account_id, env::block_timestamp()).as_bytes()),
                        };
                        let mut new_set = UnorderedSet::new(temp_key);
                        
                        for token_id in valid_tokens {
                            new_set.insert(&token_id);
                        }

                        // Save the cleaned set
                        if new_set.is_empty() {
                            self.tokens_per_owner.remove(account_id);
                            log_str(&format!("Removed empty set for account: {}", account_id));
                        } else {
                            self.tokens_per_owner.insert(account_id, &new_set);
                            log_str(&format!("Updated set for account: {}", account_id));
                        }
                    }
                }
            }
        } else {
            log_str(&format!("No account found at index {}", target_index));
        }

        // Get final storage usage and calculate difference
        let final_storage = env::storage_usage();
        let storage_freed = if final_storage < initial_storage {
            initial_storage - final_storage
        } else {
            0
        };

        // Calculate storage cost in NEAR
        let storage_cost_near = storage_freed as f64 * 0.0001;  // 0.0001 NEAR per byte

        log_str(&format!(
            "Single account cleanup complete:\n- Freed {} bytes of storage (approximately {} NEAR)",
            storage_freed,
            storage_cost_near
        ));
    }

    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) {
        let storage_account_id = account_id
            .map(|a| a.into())
            .unwrap_or_else(env::predecessor_account_id);

        let deposit = env::attached_deposit().as_yoctonear();
        
        // No need to check if deposit >= 0 since it's an unsigned integer
        
        // Transfer the deposit to the contract to cover future storage costs
        Promise::new(env::current_account_id())
            .transfer(NearToken::from_yoctonear(deposit));

        log_str(&format!(
            "Received storage deposit of {} yoctoNEAR for account {}",
            deposit,
            storage_account_id
        ));
    }

    #[payable]
    pub fn admin_distribute_tokens(&mut self) -> Promise {
        // Only owner can distribute tokens
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can distribute tokens"
        );

        // Get contract's token balance first
        Promise::new(self.ft_token_id.clone())
            .function_call(
                "ft_balance_of".to_string(),
                json!({
                    "account_id": env::current_account_id()
                })
                .to_string()
                .into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(5)
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(180))
                    .on_get_balance_for_distribution()
            )
    }

    #[private]
    pub fn on_get_balance_for_distribution(&mut self) -> Promise {
        assert_eq!(env::promise_results_count(), 1, "Expected 1 promise result");
        
        let balance: U128 = match env::promise_result(0) {
            PromiseResult::Successful(value) => near_sdk::serde_json::from_slice(&value).unwrap(),
            _ => {
                log_str("Failed to get balance");
                return Promise::new(env::current_account_id());
            }
        };

        log_str(&format!("Distributing balance of {}", balance.0));

        let mut promise = Promise::new(self.ft_token_id.clone());
        let mut remaining_amount = balance.0;

        // Process all wallets except the last one
        for wallet in self.payout_wallets.iter().take(self.payout_wallets.len() - 1) {
            let share_u128 = u128::from(wallet.share);
            let wallet_amount = (balance.0 * share_u128) / 100u128;
            remaining_amount = remaining_amount.saturating_sub(wallet_amount);

            if wallet_amount > 0 {
                promise = promise.then(
                    Promise::new(self.ft_token_id.clone())
                        .function_call(
                            "ft_transfer".to_string(),
                            json!({
                                "receiver_id": wallet.account_id,
                                "amount": U128(wallet_amount),
                                "memo": Some(format!("Payout share: {}%", wallet.share))
                            })
                            .to_string()
                            .into_bytes(),
                            NearToken::from_yoctonear(1),
                            Gas::from_tgas(10)
                        )
                );

                log_str(&format!(
                    "Scheduled transfer of {} tokens to {} ({}%)",
                    wallet_amount,
                    wallet.account_id,
                    wallet.share
                ));
            }
        }

        // Send remaining amount to last wallet
        if let Some(last_wallet) = self.payout_wallets.last() {
            if remaining_amount > 0 {
                promise = promise.then(
                    Promise::new(self.ft_token_id.clone())
                        .function_call(
                            "ft_transfer".to_string(),
                            json!({
                                "receiver_id": last_wallet.account_id,
                                "amount": U128(remaining_amount),
                                "memo": Some(format!("Final payout share: {}%", last_wallet.share))
                            })
                            .to_string()
                            .into_bytes(),
                            NearToken::from_yoctonear(1),
                            Gas::from_tgas(10)
                        )
                );

                log_str(&format!(
                    "Scheduled final transfer of {} tokens to {} ({}%)",
                    remaining_amount,
                    last_wallet.account_id,
                    last_wallet.share
                ));
            }
        }

        promise
    }

    // Add a view method to check contract's token balance
    pub fn get_contract_token_balance(&self) -> Promise {
        Promise::new(self.ft_token_id.clone())
            .function_call(
                "ft_balance_of".to_string(),
                json!({
                    "account_id": env::current_account_id()
                })
                .to_string()
                .into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(5)
            )
    }

    /// Returns a list of unminted token IDs within the specified range
    pub fn get_unminted_tokens(&self, start: u64, end: u64) -> Vec<String> {
        assert!(end >= start, "End must be greater than or equal to start");
        assert!(end <= self.max_supply, "End cannot exceed max supply");
        
        let mut unminted = Vec::new();
        for id in start..=end {
            let token_id = id.to_string();
            if !self.token_ids.contains(&token_id) {
                unminted.push(token_id);
            }
        }
        
        unminted
    }

    /// Returns the total number of minted tokens
    pub fn get_total_minted(&self) -> u64 {
        self.total_supply
    }

    /// Returns the next available token ID
    pub fn get_next_available_id(&self) -> String {
        self.get_next_token_id()
    }

    /// Diagnostic function to check token counts and next available ID
    pub fn check_token_status(&self) -> String {
        let total_supply = self.total_supply;
        let tokens_in_set = self.token_ids.len();
        
        // Find the actual next available ID
        let mut next_available = 0;
        while self.token_ids.contains(&next_available.to_string()) {
            next_available += 1;
            if next_available >= self.max_supply {
                break;
            }
        }

        // Get a sample of existing tokens
        let mut sample_tokens = Vec::new();
        let mut count = 0;
        for id in 0..std::cmp::min(10, self.max_supply) {
            if self.token_ids.contains(&id.to_string()) {
                sample_tokens.push(id);
                count += 1;
                if count >= 5 {
                    break;
                }
            }
        }

        format!(
            "Status:\n\
             Total Supply Counter: {}\n\
             Actual Tokens in Set: {}\n\
             Next Available ID: {}\n\
             Sample of Existing Tokens: {:?}\n\
             Max Supply: {}",
            total_supply,
            tokens_in_set,
            next_available,
            sample_tokens,
            self.max_supply
        )
    }

    /// Get basic stats about token status
    pub fn get_token_stats(&self) -> (u64, u64, u64) {
        (
            self.total_supply,      // Total supply counter
            self.token_ids.len(),   // Actual tokens in set
            self.max_supply         // Max supply
        )
    }

    /// Check if a specific token ID exists
    pub fn token_exists(&self, token_id: String) -> bool {
        self.token_ids.contains(&token_id)
    }

    /// Get a range of token existence status
    pub fn check_token_range(&self, start: u64, end: u64) -> Vec<bool> {
        assert!(end >= start, "End must be greater than start");
        assert!(end - start <= 100, "Can only check 100 tokens at a time");
        
        let mut results = Vec::with_capacity((end - start) as usize);
        for id in start..end {
            results.push(self.token_ids.contains(&id.to_string()));
        }
        results
    }

    /// Find the first available token ID in a range
    pub fn find_first_available(&self, start: u64, end: u64) -> Option<u64> {
        assert!(end >= start, "End must be greater than start");
        assert!(end - start <= 100, "Can only check 100 tokens at a time");
        
        for id in start..end {
            if !self.token_ids.contains(&id.to_string()) {
                return Some(id);
            }
        }
        None
    }
}

// Fix the approval receiver interface name to match the call
#[ext_contract(ext_approval_receiver)]
pub trait ApprovalReceiver {
    fn nft_on_approve(
        &mut self,
        token_id: TokenId,
        owner_id: AccountId,
        approval_id: u64,
        msg: String,
    ) -> Promise;
}

fn assert_at_least_one_yocto() {
    assert!(
        env::attached_deposit() >= NearToken::from_yoctonear(1),
        "Requires attached deposit of at least 1 yoctoNEAR"
    );
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct DebugTokenInfo {
    token_id: TokenId,
    owner_from_nft_token: Option<AccountId>,
    found_in_tokens_per_owner: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct DebugOwnerInfo {
    count: u64,
    has_set: bool,
    example_tokens: Vec<TokenId>
}
