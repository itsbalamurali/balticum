use crate::smart_id::authentication_request_builder::AuthenticationRequestBuilder;
use crate::smart_id::session_status_fetcher::SessionStatusFetcherBuilder;
use crate::smart_id::session_status_poller::SessionStatusPoller;
use crate::smart_id::smart_id_client::{ SmartIdClient};
use crate::smart_id::smart_id_request_builder::SmartIdRequestBuilder;
use crate::smart_id::smart_id_rest_connector::SmartIdRestConnector;

pub struct AuthenticationApi<'a> {
    client: &'a SmartIdClient,
    polling_sleep_timeout_ms: u64,
    session_status_response_socket_timeout_ms: u64,
}


impl<'a> AuthenticationApi<'a> {
    pub fn new(client: &SmartIdClient) -> AuthenticationApi {
        AuthenticationApi {
            client,
            polling_sleep_timeout_ms: 500,
            session_status_response_socket_timeout_ms: 10000,
        }
    }

    pub fn create_authentication(&self) -> AuthenticationRequestBuilder {
        let mut connector = SmartIdRestConnector::new(self.client.get_host_url());
        connector.set_public_ssl_keys(self.client.get_public_ssl_keys());
        let mut session_status_poller = self.create_session_status_poller();
        let mut builder = SmartIdRequestBuilder::new(&connector, self.client.get_host_url());
        builder.with_relying_party_details(self.client.get_relying_party_uuid(),self.client.get_relying_party_name());
        AuthenticationRequestBuilder::new(self.client.get_host_url())
    }

    pub fn create_session_status_fetcher(&self) -> SessionStatusFetcherBuilder {
        let mut connector = SmartIdRestConnector::new(self.client.get_host_url());
        connector.set_public_ssl_keys(self.client.get_public_ssl_keys());
        let builder = SessionStatusFetcherBuilder::new(self.client.get_host_url());
        builder
            .with_session_status_response_socket_timeout_ms(
                self.session_status_response_socket_timeout_ms,
            )
            .unwrap()
    }

    fn create_session_status_poller(&'a self) -> SessionStatusPoller {
        let mut session_status_poller = SessionStatusPoller::new(self.client.get_host_url());
        session_status_poller.set_polling_sleep_timeout_ms(self.polling_sleep_timeout_ms);
        session_status_poller.set_session_status_response_socket_timeout_ms(
            self.session_status_response_socket_timeout_ms,
        );
        session_status_poller
    }

    pub fn set_polling_sleep_timeout_ms(
        &mut self,
        polling_sleep_timeout_ms: u64,
    ) -> Result<(), String> {
        self.polling_sleep_timeout_ms = polling_sleep_timeout_ms;
        Ok(())
    }

    pub fn set_session_status_response_socket_timeout_ms(
        &mut self,
        session_status_response_socket_timeout_ms: u64,
    ) -> Result<(), String> {
        self.session_status_response_socket_timeout_ms = session_status_response_socket_timeout_ms;
        Ok(())
    }
}
