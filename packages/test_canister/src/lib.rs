use std::cell::RefCell;

use candid::Principal;
use ic_cdk::{init, query};

type GetAddressResponse = Result<String, String>;

thread_local! {
    static SIWE_PROVIDER_CANISTER: RefCell<Option<Principal>>  = const { RefCell::new(None) };
}

/// The whoami method returns the calling principal and the eth address of the caller. A prerequisite
/// for a successful response is that the test canister has been initialized with a reference to the siwe
/// provider canister and that the caller has completed the authentication process with the siwe
/// provider canister.
#[query]
async fn whoami() -> Result<(String, String), String> {
    let calling_principal = ic_cdk::caller();

    // Get the siwe provider canister reference
    let siwe_provider_canister = SIWE_PROVIDER_CANISTER
        .with_borrow(|canister| canister.expect("Siwe provider canister not initialized"));

    // Call the get_address method on the siwe provider canister with the calling principal as an argument
    let response: Result<(GetAddressResponse,), _> = ic_cdk::call(
        siwe_provider_canister,
        "get_address",
        (calling_principal.as_slice(),),
    )
    .await;

    let address = match response {
        Ok(inner_result) => {
            // Handle the inner Result (GetAddressResponse)
            match inner_result.0 {
                Ok(address) => address,  // Successfully got the address
                Err(e) => return Err(e), // Handle error in GetAddressResponse
            }
        }
        Err(_) => return Err("Failed to get the caller address".to_string()), // Handle ic_cdk::call error
    };

    // Return the calling principal and address
    Ok((calling_principal.to_text(), address))
}

/// When setting up the test canister, we need to save a reference to the siwe provider canister
/// so that we can call it later.
#[init]
async fn init(siwe_provider_canister: String) {
    // Save a reference to the siwe provider canister
    SIWE_PROVIDER_CANISTER.with(|canister| {
        *canister.borrow_mut() =
            Some(Principal::from_text(siwe_provider_canister).expect("Invalid principal"));
    });
}
