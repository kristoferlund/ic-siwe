use candid::{CandidType, Principal};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use simple_asn1::ASN1EncodeErr;
use std::fmt;

use crate::{
    delegation::{
        create_delegation, create_delegation_hash, create_user_canister_pubkey, generate_seed,
        DelegationError,
    },
    eth::{recover_eth_address, EthAddress, EthError, EthSignature},
    hash,
    rand::generate_nonce,
    settings::Settings,
    signature_map::SignatureMap,
    siwe::{SiweMessage, SiweMessageError},
    time::get_current_time,
    with_settings, SIWE_MESSAGES,
};
use simple_asn1::from_der;

// Increased from 10 to prevent state exhaustion. Pruning is relatively cheap, so we can afford to prune more.
const MAX_SIGS_TO_PRUNE: usize = 1000;

/// This function is the first step of the user login process. It validates the provided Ethereum address,
/// creates a SIWE message, saves it for future use, and returns it.
///
/// # Parameters
/// * `address`: A [`crate::eth::EthAddress`] representing the user's Ethereum address. This address is
///   validated and used to create the SIWE message.
/// * `principal`: The [`Principal`] of the caller, used to uniquely store the SIWE message.
///
/// # Returns
/// A `Result` that, on success, contains a [`crate::siwe::SiweMessage`].
///
/// # Example
/// ```ignore
/// use ic_siwe::{
///   login::prepare_login,
///   eth::EthAddress
/// };
/// use candid::Principal;
///
/// let address = EthAddress::new("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
/// let principal = Principal::from_text("aaaaa-aa").unwrap(); // Example principal
/// let message = prepare_login(&address, &principal).unwrap();
/// ```
pub fn prepare_login(address: &EthAddress, principal: &Principal) -> Result<SiweMessage, EthError> {
    let nonce = generate_nonce();
    let message = SiweMessage::new(address, &nonce);

    // Save the SIWE message for use in the login call
    SIWE_MESSAGES.with_borrow_mut(|siwe_messages| {
        siwe_messages.insert(message.clone(), address, principal);
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
    SessionKeyMismatch,
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
            LoginError::EthError(e) => write!(f, "{e}"),
            LoginError::SiweMessageError(e) => write!(f, "{e}"),
            LoginError::AddressMismatch => write!(f, "Recovered address does not match"),
            LoginError::SessionKeyMismatch => {
                write!(f, "Session key does not match calling principal")
            }
            LoginError::DelegationError(e) => write!(f, "{e}"),
            LoginError::ASN1EncodeErr(e) => write!(f, "{e}"),
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
        // Prune any expired SIWE messages from the state.
        siwe_messages.prune_expired();

        // Validate the session key before use
        if session_key.is_empty() {
            return Err(LoginError::DelegationError(
                DelegationError::InvalidSessionKey("Session key is empty".to_string()),
            ));
        }

        // Verify the session key is properly DER-encoded
        from_der(&session_key).map_err(|e| {
            LoginError::DelegationError(DelegationError::InvalidSessionKey(format!(
                "Session key should be DER-encoded: {e}"
            )))
        })?;

        // Get the previously created SIWE message for current address / principal combination. If it has
        // expired or does not exist, return an error.
        let session_principal = Principal::self_authenticating(session_key.clone());
        let message = siwe_messages.get(address, &session_principal)?;
        let message_string: String = message.clone().into();

        // Verify the supplied signature against the SIWE message and recover the Ethereum address
        // used to sign the message.
        let result = match recover_eth_address(&message_string, signature) {
            Ok(recovered_address) => {
                if recovered_address != address.as_str() {
                    Err(LoginError::AddressMismatch)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(LoginError::EthError(e)),
        };

        // Ensure the SIWE message is removed from the state both on success and on failure.
        siwe_messages.remove(address, &session_principal);

        // Handle the result of the signature verification.
        result?;

        // The delegation is valid for the duration of the session as defined in the settings,
        // measured from the login time (now)
        let expiration = with_settings!(|settings: &Settings| {
            get_current_time().saturating_add(settings.session_expires_in)
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
        let user_canister_pubkey = create_user_canister_pubkey(*canister_id, seed.to_vec());

        Ok(LoginDetails {
            expiration,
            user_canister_pubkey: ByteBuf::from(user_canister_pubkey),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{settings::SettingsBuilder, SETTINGS};
    use ethers::{
        core::rand::thread_rng,
        signers::{LocalWallet, Signer},
        utils::{hash_message, to_checksum},
    };

    // DER-encoded session key (valid)
    const SESSION_KEY: &[u8] = &[
        48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 220, 227, 2, 129, 72, 36, 43, 220, 96, 102,
        225, 92, 98, 163, 114, 182, 117, 181, 51, 15, 219, 197, 104, 55, 123, 245, 74, 181, 35,
        181, 171, 196,
    ];

    fn init_settings() {
        let settings = SettingsBuilder::new("example.com", "http://example.com", "salt")
            .statement("Login to the app")
            .sign_in_expires_in(60_000_000_000) // 60s
            .session_expires_in(600_000_000_000) // 10m
            .build()
            .unwrap();
        SETTINGS.set(Some(settings));
    }

    #[test]
    fn login_happy_path() {
        init_settings();
        let mut sig_map = SignatureMap::default();
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();

        // create an eth wallet and address
        let wallet = LocalWallet::new(&mut thread_rng());
        let addr_eip55 = to_checksum(&wallet.address(), None);
        let address = EthAddress::new(&addr_eip55).unwrap();

        // session principal derived from key used for prepare_login
        let session_key = ByteBuf::from(SESSION_KEY);
        let session_principal = Principal::self_authenticating(session_key.clone());

        // prepare login to store SIWE message for (address, session_principal)
        let siwe_message = prepare_login(&address, &session_principal).unwrap();
        // sign the EIP-4361 string using EIP-191
        let siwe_string: String = siwe_message.clone().into();
        let sig = wallet
            .sign_hash(hash_message(siwe_string.as_bytes()))
            .unwrap();
        let signature = EthSignature::new(&format!("0x{}", sig)).unwrap();

        // perform login
        let start = get_current_time();
        let details = match login(
            &signature,
            &address,
            session_key.clone(),
            &mut sig_map,
            &canister_id,
        ) {
            Ok(d) => d,
            Err(e) => panic!("login should succeed: {e}"),
        };
        let end = get_current_time();

        // expiration is based on login time: in [start + TTL, end + TTL]
        let ttl = with_settings!(|s: &Settings| s.session_expires_in);
        assert!(
            details.expiration >= start + ttl && details.expiration <= end + ttl,
            "expiration not within expected login-time window"
        );
        assert!(!details.user_canister_pubkey.is_empty());
    }

    #[test]
    fn login_address_mismatch() {
        init_settings();
        let mut sig_map = SignatureMap::default();
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();

        // correct wallet/address
        let wallet = LocalWallet::new(&mut thread_rng());
        let addr_eip55 = to_checksum(&wallet.address(), None);
        let address = EthAddress::new(&addr_eip55).unwrap();

        // different address used at login (fresh wallet)
        let other = {
            let w = LocalWallet::new(&mut thread_rng());
            let a = to_checksum(&w.address(), None);
            EthAddress::new(&a).unwrap()
        };

        let session_key = ByteBuf::from(SESSION_KEY);
        let p = Principal::self_authenticating(session_key.clone());

        let siwe_message = prepare_login(&address, &p).unwrap();
        let siwe_string: String = siwe_message.into();
        let sig = wallet
            .sign_hash(hash_message(siwe_string.as_bytes()))
            .unwrap();
        let signature = EthSignature::new(&format!("0x{}", sig)).unwrap();

        let err = login(&signature, &other, session_key, &mut sig_map, &canister_id).unwrap_err();
        // The message is stored for the original address + session principal; looking up with a different
        // address yields 'Message not found' (never reaching signature check).
        assert_eq!(err.to_string(), "Message not found");
    }

    #[test]
    fn login_empty_session_key() {
        init_settings();

        let wallet = LocalWallet::new(&mut thread_rng());
        let address = EthAddress::new(&to_checksum(&wallet.address(), None)).unwrap();
        let principal = Principal::from_slice(&[1; 29]);

        // Prepare login first
        let message = prepare_login(&address, &principal).unwrap();
        let message_string: String = message.into();
        let hash = hash_message(message_string.as_bytes());
        let signature = wallet.sign_hash(hash).unwrap();
        let signature_hex = format!("0x{}", hex::encode(signature.to_vec()));

        // Create an empty session key
        let empty_session_key = ByteBuf::new();
        let eth_signature = EthSignature::new(&signature_hex).unwrap();
        let mut signature_map = SignatureMap::default();
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();

        let result = login(
            &eth_signature,
            &address,
            empty_session_key,
            &mut signature_map,
            &canister_id,
        );

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid session key: Session key is empty"
        );
    }

    #[test]
    fn login_invalid_der_session_key() {
        init_settings();

        let wallet = LocalWallet::new(&mut thread_rng());
        let address = EthAddress::new(&to_checksum(&wallet.address(), None)).unwrap();
        let principal = Principal::from_slice(&[1; 29]);

        // Prepare login first
        let message = prepare_login(&address, &principal).unwrap();
        let message_string: String = message.into();
        let hash = hash_message(message_string.as_bytes());
        let signature = wallet.sign_hash(hash).unwrap();
        let signature_hex = format!("0x{}", hex::encode(signature.to_vec()));

        // Create an invalid DER-encoded session key
        let invalid_session_key = ByteBuf::from(vec![0xFF, 0xFF, 0xFF, 0xFF]);
        let eth_signature = EthSignature::new(&signature_hex).unwrap();
        let mut signature_map = SignatureMap::default();
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();

        let result = login(
            &eth_signature,
            &address,
            invalid_session_key,
            &mut signature_map,
            &canister_id,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Session key should be DER-encoded"));
    }
}
