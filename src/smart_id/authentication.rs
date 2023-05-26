use crate::smart_id::authentication_request_builder::AuthenticationRequestBuilder;
use crate::smart_id::session_status_fetcher::SessionStatusFetcherBuilder;
use crate::smart_id::session_status_poller::SessionStatusPoller;
use crate::smart_id::smart_id_client::{AbstractApi, SmartIdClient};
use crate::smart_id::smart_id_request_builder::SmartIdRequestBuilder;
use crate::smart_id::smart_id_rest_connector::SmartIdRestConnector;

pub struct AuthenticationApi<'a> {
    client: &'a SmartIdClient,
    polling_sleep_timeout_ms: u64,
    session_status_response_socket_timeout_ms: u64,
}

impl AbstractApi for AuthenticationApi<'_> {

}

impl AuthenticationApi<'_> {

    pub fn new(client: &SmartIdClient) -> Self {
        AuthenticationApi {
            client,
            polling_sleep_timeout_ms: 500,
            session_status_response_socket_timeout_ms: 10000,
        }
    }

    pub fn create_authentication(&self) -> AuthenticationRequestBuilder {
        let mut connector = SmartIdRestConnector::new(self.client.get_host_url());
        connector.set_public_ssl_keys(self.client.get_public_ssl_keys());
        let session_status_poller = self.create_session_status_poller(connector);
        let mut builder = SmartIdRequestBuilder::new(&connector, session_status_poller);
        self.populate_builder_fields(&mut builder);
        AuthenticationRequestBuilder::new(&connector,&session_status_poller)

    }

    pub fn create_session_status_fetcher(&self) -> SessionStatusFetcherBuilder {
        let mut connector = SmartIdRestConnector::new(self.client.get_host_url());
        connector.set_public_ssl_keys(self.client.get_public_ssl_keys());
        let builder = SessionStatusFetcherBuilder::new(&connector);
        builder.with_session_status_response_socket_timeout_ms(self.session_status_response_socket_timeout_ms).unwrap()
    }

    fn populate_builder_fields(&self, builder: &mut SmartIdRequestBuilder) {
        builder.with_relying_party_uuid(self.client.get_relying_party_uuid())
            .with_relying_party_name(self.client.get_relying_party_name());
    }

    fn create_session_status_poller(&self, connector: SmartIdRestConnector) -> SessionStatusPoller {
        let mut session_status_poller = SessionStatusPoller::new(&connector);
        session_status_poller.set_polling_sleep_timeout_ms(self.polling_sleep_timeout_ms);
        session_status_poller.set_session_status_response_socket_timeout_ms(self.session_status_response_socket_timeout_ms);
        session_status_poller
    }

    pub fn set_polling_sleep_timeout_ms(&mut self, polling_sleep_timeout_ms: u64) -> Result<(), String> {
        if polling_sleep_timeout_ms < 0 {
            return Err(String::from("Timeout cannot be negative"));
        }
        self.polling_sleep_timeout_ms = polling_sleep_timeout_ms;
        Ok(())
    }

    pub fn set_session_status_response_socket_timeout_ms(&mut self, session_status_response_socket_timeout_ms: u64) -> Result<(), String> {
        if session_status_response_socket_timeout_ms < 0 {
            return Err(String::from("Timeout cannot be negative"));
        }
        self.session_status_response_socket_timeout_ms = session_status_response_socket_timeout_ms;
        Ok(())
    }
}

