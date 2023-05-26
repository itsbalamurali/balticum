use smart_id_rs::smart_id::smart_id_client::SmartIdClient;

fn main() {
    println!("Hello, world!");

    let mut client = SmartIdClient::new();
    client
        .set_relying_party_uuid( DummyData::DEMO_RELYING_PARTY_UUID )
        .set_relying_party_name( DummyData::DEMO_RELYING_PARTY_NAME )
        .set_public_ssl_keys("sha256//Ps1Im3KeB0Q4AlR+/J9KFd/MOznaARdwo4gURPCLaVA=".to_string())
        .set_host_url( DummyData::DEMO_HOST_URL );
}