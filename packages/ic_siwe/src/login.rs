use std::fmt;

use candid::{CandidType, Principal};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use simple_asn1::ASN1EncodeErr;

use crate::{
    delegation::{
        create_delegation, create_delegation_hash, create_user_canister_pubkey, generate_seed,
        DelegationError,
    },
    eth::{recover_eth_address, EthAddress, EthError, EthSignature},
    hash,
    settings::Settings,
    signature_map::SignatureMap,
    siwe::{SiweMessage, SiweMessageError},
    time::get_current_time,
    with_settings, SIWE_MESSAGES,
};

const MAX_SIGS_TO_PRUNE: usize = 10;

/// This function is the first step of the user login process. It validates the provided Ethereum address,
/// creates a SIWE message, saves it for future use, and returns it.
///
/// # Parameters
/// * `address`: A string slice (`&str`) representing the user's Ethereum address. This address is
///   validated and used to create the SIWE message.
///
/// # Returns
/// A `Result` that, on success, contains the `SiweMessage` for the user, or an error string on failure.
///
/// # Example
/// ```ignore
/// use ic_siwe::{
///   login::prepare_login,
///   eth::EthAddress
/// };
///
/// let address = EthAddress::new("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
/// let message = prepare_login(&address).unwrap();
/// ```
pub fn prepare_login(address: &EthAddress) -> Result<SiweMessage, EthError> {
    let message = SiweMessage::new(address);

    // Save the SIWE message for use in the login call
    SIWE_MESSAGES.with_borrow_mut(|siwe_messages| {
        siwe_messages.insert(address.as_bytes(), message.clone());
    });

    Ok(message)
}
/// Login details are returned after a successful login. They contain the expiration time of the
/// delegation and the user canister public key.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LoginDetails {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,

    /// The user canister public key. This key is used to derive the user principal.
    pub user_canister_pubkey: ByteBuf,
}

pub enum LoginError {
    EthError(EthError),
    SiweMessageError(SiweMessageError),
    AddressMismatch,
    DelegationError(DelegationError),
    ASN1EncodeErr(ASN1EncodeErr),
}

impl From<EthError> for LoginError {
    fn from(err: EthError) -> Self {
        LoginError::EthError(err)
    }
}

impl From<SiweMessageError> for LoginError {
    fn from(err: SiweMessageError) -> Self {
        LoginError::SiweMessageError(err)
    }
}

impl From<DelegationError> for LoginError {
    fn from(err: DelegationError) -> Self {
        LoginError::DelegationError(err)
    }
}

impl From<ASN1EncodeErr> for LoginError {
    fn from(err: ASN1EncodeErr) -> Self {
        LoginError::ASN1EncodeErr(err)
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::EthError(e) => write!(f, "{}", e),
            LoginError::SiweMessageError(e) => write!(f, "{}", e),
            LoginError::AddressMismatch => write!(f, "Recovered address does not match"),
            LoginError::DelegationError(e) => write!(f, "{}", e),
            LoginError::ASN1EncodeErr(e) => write!(f, "{}", e),
        }
    }
}

/// Handles the second step of the user login process. It verifies the signature against the SIWE message,
/// creates a delegation for the session, adds it to the signature map, and returns login details
///
/// # Parameters
/// * `signature`: The SIWE message signature to verify.
/// * `address`: The Ethereum address used to sign the SIWE message.
/// * `session_key`: A unique session key to be used for the delegation.
/// * `signature_map`: A mutable reference to `SignatureMap` to which the delegation hash will be added
///   after successful validation.
/// * `canister_id`: The principal of the canister performing the login.
///
/// # Returns
/// A `Result` that, on success, contains the [LoginDetails] with session expiration and user canister
/// public key, or an error string on failure.
pub fn login(
    signature: &EthSignature,
    address: &EthAddress,
    session_key: ByteBuf,
    signature_map: &mut SignatureMap,
    canister_id: &Principal,
) -> Result<LoginDetails, LoginError> {
    // Remove expired SIWE messages from the state before proceeding. The init settings determines
    // the time to live for SIWE messages.
    SIWE_MESSAGES.with_borrow_mut(|siwe_messages| {
        siwe_messages.prune();
        // prune_expired_siwe_messages();

        // Get the previously created SIWE message for current address. If it has expired or does not
        // exist, return an error.
        let address_bytes = address.as_bytes();
        let message = siwe_messages.get(&address_bytes)?;

        let message_string: String = message.clone().into();

        // Verify the supplied signature against the SIWE message and recover the Ethereum address
        // used to sign the message.
        let recovered_address = recover_eth_address(&message_string, signature)?;
        if recovered_address != address.as_str() {
            return Err(LoginError::AddressMismatch);
        }

        // At this point, the signature has been verified and the SIWE message has been used. Remove
        // the SIWE message from the state.
        siwe_messages.remove(&address_bytes);

        // The delegation is valid for the duration of the session as defined in the settings.
        let expiration = with_settings!(|settings: &Settings| {
            message
                .issued_at
                .saturating_add(settings.session_expires_in)
        });

        // The seed is what uniquely identifies the delegation. It is derived from the salt, the
        // Ethereum address and the SIWE message URI.
        let seed = generate_seed(address);

        // Before adding the signature to the signature map, prune any expired signatures.
        signature_map.prune_expired(get_current_time(), MAX_SIGS_TO_PRUNE);

        // Create the delegation and add its hash to the signature map. The seed is used as the map key.
        let delegation = create_delegation(session_key, expiration)?;
        let delegation_hash = create_delegation_hash(&delegation);
        signature_map.put(hash::hash_bytes(seed), delegation_hash);

        // Create the user canister public key from the seed. From this key, the client can derive the
        // user principal.
        let user_canister_pubkey = create_user_canister_pubkey(canister_id, seed.to_vec())?;

        Ok(LoginDetails {
            expiration,
            user_canister_pubkey: ByteBuf::from(user_canister_pubkey),
        })
    })
}
