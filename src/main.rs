use balticum::{
    mobile_id::{
        models::{DisplayTextFormat, Language},
        MobileIdClient,
    },
    smart_id::{
        models::{self, AuthenticationHash},
    },
};
use balticum::smart_id::models::{CertificateLevel, Interaction, SessionStatusCode};
use balticum::smart_id::SmartIdClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test Smart-ID authentication
    let auth_hash = AuthenticationHash::new_random_hash(models::HashType::Sha512);
    let client = SmartIdClient::new(
        "https://sid.demo.sk.ee/smart-id-rp/v2/".to_string(),
        "00000000-0000-0000-0000-000000000000".to_string(),
        "DEMO".to_string(),
        auth_hash.to_owned(),
        None,
        Vec::new(),
    );
    let auth_session = client
        .authenticate_with_document_number(
            "PNOEE-50001029996-MOCK-Q".to_string(),
            None,
            CertificateLevel::Qualified,
            vec![
                Interaction::of_type_display_text_and_pin("display_text".to_string()),
            ],
            None
        )
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
    let cert = auth_response.cert.unwrap().get_x509_certificate().unwrap();
    println!("{:?}", cert.issuer_common_name().unwrap());

    // Test Mobile-ID authentication
    let client = MobileIdClient::new(
        "https://tsp.demo.sk.ee/mid-api".to_string(),
        "00000000-0000-0000-0000-000000000000".to_string(),
        "DEMO".to_string(),
    );
    let auth_session = client
        .send_authentication_request(
            "+37268000769".to_string(),
            "60001017869".to_string(),
            auth_hash.to_owned(),
            Language::ENG,
            "display_text".to_string(),
            DisplayTextFormat::GSM7,
        )
        .await
        .unwrap();

    println!("Auth Session: {:?}", auth_session);

    let session_status = client
        .get_authentication_session_status(auth_session.session_id.unwrap(),None)
        .await
        .unwrap();

    println!("Session Status: {}", session_status.get_cert().unwrap().issuer_common_name().unwrap());

    Ok(())
}
