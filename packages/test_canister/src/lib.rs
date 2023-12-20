use ic_cdk::query;

#[query]
fn whoami() -> Result<String, String> {
    let principal = ic_cdk::caller();
    Ok(principal.to_text())
}
