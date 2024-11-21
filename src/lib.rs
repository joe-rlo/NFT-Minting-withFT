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

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TokenMetadata {
    pub title: Option<String>,       // ex. "Arch Nemesis: Mail Carrier" or "Parcel #5055"
    pub description: Option<String>, // free-form description
    pub media: Option<String>,       // URL to associated media, preferably to decentralized, content-addressed storage
    pub media_hash: Option<Base64VecU8>, // Base64-encoded sha256 hash of content referenced by the `media` field
    pub copies: Option<u64>,         // number of copies of this set of metadata in existence when token was minted
    pub issued_at: Option<u64>,      // When token was issued or minted
    pub expires_at: Option<u64>,     // When token expires
    pub starts_at: Option<u64>,      // When token starts being valid
    pub updated_at: Option<u64>,     // When token was last updated
    pub extra: Option<String>,       // anything extra the NFT wants to store on-chain
    pub reference: Option<String>,   // URL to an off-chain JSON file with more info
    pub reference_hash: Option<Base64VecU8>, // Base64-encoded sha256 hash of JSON from reference field
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TokenData {
    pub token_id: String,
    pub owner_id: String,
    pub metadata: TokenMetadata,
    pub approved_account_ids: HashMap<AccountId, u64>,
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

        Self {
            owner_id,
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
        }
    }

    #[payable]
    pub fn mint_many(&mut self, number_of_tokens: u64) -> Vec<TokenData> {
        // This function should not be called directly anymore
        unimplemented!("Please use FT transfer to mint tokens");
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
            let token_id = format!("{}", self.total_supply + 1);
            
            // Create metadata for this token
            let metadata = TokenMetadata {
                title: Some(format!("{} #{}", self.metadata.name, token_id)),
                description: Some(format!("Token {} from collection {}", token_id, self.metadata.name)),
                media: self.metadata.base_uri.clone().map(|uri| format!("{}/{}.png", uri, token_id)),
                media_hash: None,
                copies: Some(1),
                issued_at: Some(env::block_timestamp()),
                expires_at: None,
                starts_at: None,
                updated_at: None,
                extra: None,
                reference: Some(format!("{}/{}.json", self.metadata.reference, token_id)),
                reference_hash: None,
            };

            // Store token data
            tokens_set.insert(&token_id);
            self.token_metadata.insert(&token_id, &metadata);
            self.token_ids.insert(&token_id);
            self.total_supply += 1;

            // Add to return vector
            minted_tokens.push(TokenData {
                token_id: token_id.clone(),
                owner_id: receiver_id.to_string(),
                metadata,
                approved_account_ids: HashMap::new(),
            });
        }

        // Save the updated token set for this owner
        self.tokens_per_owner.insert(receiver_id, &tokens_set);

        minted_tokens
    }

    // Single implementation of distribute_payment
    fn distribute_payment(&mut self, amount: U128) {
        let mut remaining_amount = amount.0;
        
        for wallet in &self.payout_wallets {
            let wallet_share = (remaining_amount as f64 * (wallet.share as f64 / 100.0)) as u128;
            if wallet_share > 0 {
                ext_ft::ext(self.ft_token_id.clone())
                    .with_attached_deposit(NearToken::from_yoctonear(1))
                    .ft_transfer(
                        wallet.account_id.clone(),
                        U128(wallet_share),
                        None,
                    );
                remaining_amount -= wallet_share;
            }
        }

        // Send any dust to the first wallet
        if remaining_amount > 0 && !self.payout_wallets.is_empty() {
            ext_ft::ext(self.ft_token_id.clone())
                .with_attached_deposit(NearToken::from_yoctonear(1))
                .ft_transfer(
                    self.payout_wallets[0].account_id.clone(),
                    U128(remaining_amount),
                    None,
                );
        }
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
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

        // Log the mint event
        let nft_mint_log = json!({
            "standard": "nep171",
            "version": "1.0.0",
            "event": "nft_mint",
            "data": [{
                "owner_id": sender_id,
                "token_ids": minted_tokens.iter().map(|t| t.token_id.clone()).collect::<Vec<_>>(),
            }]
        });
        log_str(&format!("EVENT_JSON:{}", nft_mint_log.to_string()));

        // Distribute the payment
        self.distribute_payment(required_amount);

        // Return unused tokens
        PromiseOrValue::Value(U128(amount.0 - required_amount.0))
    }

    // View methods
    pub fn nft_metadata(&self) -> NFTMetadata {
        self.metadata.clone()
    }

    pub fn nft_token(&self, token_id: String) -> Option<TokenData> {
        if let Some(metadata) = self.token_metadata.get(&token_id) {
            for account_str in self.token_ids.iter() {
                // Convert String to AccountId
                let account_id: AccountId = account_str.parse().unwrap();
                if let Some(tokens) = self.tokens_per_owner.get(&account_id) {
                    if tokens.contains(&token_id) {
                        return Some(TokenData {
                            token_id,
                            owner_id: account_str,
                            metadata,
                            approved_account_ids: HashMap::new(),
                        });
                    }
                }
            }
        }
        None
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
}