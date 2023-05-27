use baltic_id::smart_id::models::{AuthenticationSessionRequest, DigestCalculator, HashType};
use baltic_id::smart_id::smart_id_client::SmartIdClient;
use baltic_id::smart_id::smart_id_rest_connector::SmartIdRestConnector;

const CERTIFICATE: &str = "MIIIFjCCBf6gAwIBAgIQDZ/p/MaW7yVhRDd0HaKZzDANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNVBAMME1RFU1Qgb2YgRUlELVNLIDIwMTYwHhcNMjEwOTE3MDYzNjM2WhcNMjQwOTE3MDYzNjM2WjB3MQswCQYDVQQGEwJMVDEgMB4GA1UEAwwXVEVTVE5VTUJFUixRVUFMSUZJRUQgT0sxEzARBgNVBAQMClRFU1ROVU1CRVIxFTATBgNVBCoMDFFVQUxJRklFRCBPSzEaMBgGA1UEBRMRUE5PTFQtMzAzMDMwMzk5MTQwggMhMA0GCSqGSIb3DQEBAQUAA4IDDgAwggMJAoIDAGtuICDz1b4qHQHEr5a+fvG5B46uce5dCGeYJTx/v26xKsKMeuOYuR3NgwzWhjzI1/E6p5NhRUbsK8LqLcNKyUYII/Njsn9tYvxZ0YgsslyVLYvuEA7Hz9zHX2w6TQyZoraDkZPnXZhc1In39Se7bPmW/FnLD3SVsPQ6Zan/muEw5U6Sn6TbkDEq5J0MuuyGOTJU7+Q3ZZ9vomwr91TfPtPuXCv6jjwpduh5ywnFe5OvxDWv1zjekjhXCNwAHQZM5rkySlEmvXRPVh/GyhYVTMyhZwYo/zC45ivS+vtJW89DczzDiwDRH6MlqLyQaI8aCRVe3+VN57WqRDBdvZr7xXTpKpNT4EPHo3ISHKporjhe513bJ/3m5BT7Ka0ksh03EFNaZB+wfYDFr2b1IlWxJwoRh01Dl+DtDM7eT03irQ1iwfbo+PWXKcLRaUsSp4Nkr0Y2YoY8yCX2WO4ZegpbrEcJw65RKMQeT3387aSujgqeCijPEUyseiiWj9CwtnCIBVYB9uemeWFI3lkL7rGctvxZ7H1zjC6UEHU8XDkS3VKzQwqYlNWYoH2Yqvn9VOb9NaKJlWFgAliOf6UJw0vQxjax9SL+VhXBEpvzZd750B9Usb29SHRs36O17hnw6/4mFXKgrde0QacWQGbOy2cdD50DiWp5jqKN3ydWgFjllY2oyhtAcuVqxTyH92HORjPxCQobHyk12SH40leemro1zGx6CdawA1r4eggobsklCO0FFtv2sRdwKMvpfWwrizrrqvzbxpNef1znJQbZlC1/bRR89bMOYEYROq5L6Qm8RAMW2cLXuHHd7j3vAQxXSbM1tA5wZZKip2oy2B1ZjV4njUv+EOHt3jyJUYKhZSfY41j0GG8dYNiZ9Plzho92D1I0JjAj0uxhtsI9BDrTgpZRmbJJqsNCKxwU/nM8Y2XUOnsM8wO1ZCjSgoxaLCiFBNbHM9lvixhzL9CNrU871+ejIN4l/TOhEcuwRCx2gase8YKxkc0X6C6O2KTnDrk6fYzF6QIDAQABo4IBrDCCAagwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBLAwXAYDVR0gBFUwUzBHBgorBgEEAc4fAxECMDkwNwYIKwYBBQUHAgEWK2h0dHBzOi8vc2tpZHNvbHV0aW9ucy5ldS9lbi9yZXBvc2l0b3J5L0NQUy8wCAYGBACPegECMB0GA1UdDgQWBBQRIaAFtP8CPI3kplr8/WiZb9wK1DAfBgNVHSMEGDAWgBSusOrhNvgmq6XMC2ZV/jodAr8StDATBgNVHSUEDDAKBggrBgEFBQcDAjB8BggrBgEFBQcBAQRwMG4wKQYIKwYBBQUHMAGGHWh0dHA6Ly9haWEuZGVtby5zay5lZS9laWQyMDE2MEEGCCsGAQUFBzAChjVodHRwOi8vc2suZWUvdXBsb2FkL2ZpbGVzL1RFU1Rfb2ZfRUlELVNLXzIwMTYuZGVyLmNydDAwBgNVHREEKTAnpCUwIzEhMB8GA1UEAwwYUE5PTFQtMzAzMDMwMzk5MTQtUEJaSy1RMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMTkwMzAzMDMxMjAwMDBaMA0GCSqGSIb3DQEBCwUAA4ICAQBIn1vWepFXmYZnviaw8AaGu2HZ2zNti4mS/YjUAA5V6rIrEGX3tPxJBVYG88h38Fjqrm6PRc4i/9hianNInjb/f1hmCAnzc6mF2yRwH1uUQ4CfLPp/V/cPo6prlqy9JERmSgDMeCh3e+C4km8pOKx9RWaNYhT5sZP9pAd19kiXAOhITUK36bCeNyWHi/LRsPcIujjR7RIuunrOpP4WZ+7di90HEo3DjFM1hQyPeiRR4PmcW0Fq8y+Tv4s7c25i1b3krIoAYzxhVstSfmLh7J4b4MhhWDSS0+klilvb8hmrHKzUjjg22nGmkVxZtvplJm/6aCfYsGCvfNZn1tn1pI2ANvH9ov6LbFej1rmpaGlu+FKRO+EXRRc7mYXdw2Ihv5fxmdcK451jqQSpn4Gep8zMZb0uWAGXw/VpWU62Ncxz4gb4WXTYTs+OqhAvBzO14c3aHli8op0Q/zTcvv6NzIvfbFZVgjqfFNnHsWcD5krS/zwE4aWciVia4Qs76Pp9cX93Kr4qsdSqdoxz/lbygCJmLPd8K5sz8mZbpUyLnARQz4xCTFUhXMYeE3VxuiWeGNO/JVUHFLWAhBQy7vXOPGW3exyPhjjH3RTTy1+bLsa3DDK9ky8Y6quuDbldFBzdoht/g+sWsAPn0air+JLH9jk+N1nQGdKBbLsLOjM62Nk/9Q==";

// valid until: 2024-03-12
const CERTIFICATE_WITHOUT_DOB_FIELD: &str = "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";

const CERTIFICATE_LEVEL: &str = "ADVANCED";
const DEMO_HOST_URL: &str = "https://sid.demo.sk.ee/smart-id-rp/v2/";

const DEMO_RELYING_PARTY_UUID: &str = "55555555-0000-0000-0000-000000000000";
const DEMO_RELYING_PARTY_NAME: &str = "DEMO PHP client";


const VALID_SEMANTICS_IDENTIFIER: &str = "PNOLT-30303039914";
const VALID_DOCUMENT_NUMBER: &str = "PNOLT-30303039914-MOCK-Q";

const SIGNABLE_TEXT: &str = "hashvalueinbase64";

const NETWORK_INTERFACE: &str = "docker0"; // network interface in machine. for example "docker0", "en7", "eth0", "127.0.0.1"


fn main() {

    let mut client = SmartIdClient::new();
    client
        .set_relying_party_uuid(DEMO_RELYING_PARTY_UUID.to_string())
        .set_relying_party_name(DEMO_RELYING_PARTY_NAME.to_string())
        .set_public_ssl_keys(vec!["sha256//Ps1Im3KeB0Q4AlR+/J9KFd/MOznaARdwo4gURPCLaVA=".to_string()])
        .set_host_url(DEMO_HOST_URL.to_string());
    }



    #[test]
    fn authenticate_demo_env_use_live_env_public_keys_should_throw_exception() {
        let mut connector = SmartIdRestConnector::new(DEMO_HOST_URL.to_string());
        connector.set_public_ssl_keys(vec!["sha256//l2uvq6ftLN4LZ+8Un+71J2vH1BT9wTbtrE5+Fj3Vc5g=;".to_string()]);
        let mut authentication_session_request = AuthenticationSessionRequest::new();
        authentication_session_request.set_relying_party_uuid(DEMO_RELYING_PARTY_UUID);
        authentication_session_request.set_relying_party_name(DEMO_RELYING_PARTY_NAME);
        authentication_session_request.set_certificate_level(CERTIFICATE_LEVEL.to_string());
        authentication_session_request.set_hash_type(HashType::Sha512);
        let hash_in_base64 =
            base64::encode(&DigestCalculator::calculate_digest(SIGNABLE_TEXT, HashType::Sha512));
        authentication_session_request.set_hash(hash_in_base64.as_str());

        let _authenticate_session_response = connector.authenticate(
            VALID_DOCUMENT_NUMBER.to_string(),
            authentication_session_request,
        );
        // assert is missing because we expect an exception to be thrown
    }

    #[test]
    #[should_panic(expected = "User account not found for URI www.google.com/authentication/document/VALID_DOCUMENT_NUMBER")]
    fn make_request_to_google_default_public_keys_should_throw_exception() {
        let mut connector = SmartIdRestConnector::new("www.google.com".to_string());
        connector.set_public_ssl_keys(vec!["".to_string()]);
        let mut authentication_session_request = AuthenticationSessionRequest::new();
        authentication_session_request
            .set_relying_party_uuid(DEMO_RELYING_PARTY_UUID);
        authentication_session_request.set_relying_party_name(DEMO_RELYING_PARTY_NAME);
        authentication_session_request.set_certificate_level(CERTIFICATE_LEVEL.to_string());
        authentication_session_request.set_hash_type(HashType::Sha512);
        let hash_in_base64 =
            base64::encode(&DigestCalculator::calculate_digest(SIGNABLE_TEXT, HashType::Sha512));
        authentication_session_request.set_hash(hash_in_base64.as_str());

        let _authenticate_session_response = connector.authenticate(
            VALID_DOCUMENT_NUMBER.to_string(),
            authentication_session_request,
        );
    }

