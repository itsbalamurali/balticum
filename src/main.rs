use e_baltica::{
    mobile_id::MobileIdClient,
    smart_id::{
        models::{AuthenticationHash, SessionStatusCode},
        SmartIdClient,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test Smart-ID authentication
    let auth_hash =
        AuthenticationHash::generate_random_hash(e_baltica::smart_id::models::HashType::Sha512);
    let client = SmartIdClient::new(
        "https://sid.demo.sk.ee/smart-id-rp/v2/".to_string(),
        "00000000-0000-0000-0000-000000000000".to_string(),
        "DEMO".to_string(),
        Some(auth_hash),
        None,
        Vec::new(),
    );
    let auth_session = client
        .authenticate_with_document_number("PNOEE-50001029996-MOCK-Q".to_string())
        .await
        .unwrap();
    let mut auth_response = client
        .get_session_status(auth_session.session_id.to_owned())
        .await
        .unwrap();
    while auth_response.get_state() != SessionStatusCode::COMPLETE {
        auth_response = client
            .get_session_status(auth_session.session_id.to_owned())
            .await
            .unwrap();
        println!("{:?}", auth_response);
    }
    let cert = auth_response.get_cert().unwrap().get_value().unwrap();
    println!("{:?}", cert);

    // Test Mobile-ID authentication
    let client = MobileIdClient::new();

    Ok(())
}
