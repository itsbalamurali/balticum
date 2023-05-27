use crate::smart_id::exceptions::Exception;
use crate::smart_id::exceptions::Exception::InvalidParametersException;
use crate::smart_id::session_status_poller::SessionStatusPoller;
use crate::smart_id::smart_id_rest_connector::SmartIdRestConnector;

pub struct SmartIdRequestBuilder<'a> {
    connector: &'a SmartIdRestConnector<'a>,
    relying_party_uuid: Option<String>,
    relying_party_name: Option<String>,
    network_interface: Option<String>,
    allowed_interactions_order: Option<Vec<String>>,
    endpoint_url: String,
}

impl<'a> SmartIdRequestBuilder<'a> {
    pub fn new(
        connector: &'a SmartIdRestConnector<'_>,
        endpoint_url: String,
    ) -> SmartIdRequestBuilder<'a> {
        SmartIdRequestBuilder {
            connector,
            endpoint_url,
            relying_party_uuid: None,
            relying_party_name: None,
            network_interface: None,
            allowed_interactions_order: None,
        }
    }

    pub fn with_relying_party_details(&'a mut self, relying_party_uuid: String, relying_party_name: String) -> &'a mut SmartIdRequestBuilder<'_> {
        self.relying_party_uuid = Some(relying_party_uuid);
        self.relying_party_name = Some(relying_party_name);
        self
    }

    pub fn with_network_interface(&'a mut self, network_interface: String) -> &'a mut SmartIdRequestBuilder<'_> {
        self.network_interface = Some(network_interface);
        self
    }

    pub fn get_connector(&self) -> &SmartIdRestConnector {
        &self.connector
    }

    pub fn get_session_status_poller(&mut self) -> SessionStatusPoller {
        let network_interface = self.get_network_interface().or_else(|| Some("")).unwrap();
        let mut session_status_poller = SessionStatusPoller::new(self.endpoint_url.clone());
        session_status_poller.set_polling_sleep_timeout_ms(1000);
        session_status_poller.set_session_status_response_socket_timeout_ms(
            1000,
        );
        session_status_poller.with_network_interface(network_interface.to_string());
        session_status_poller
    }

    pub fn get_relying_party_uuid(&self) -> Result<&str, Exception> {
        self.relying_party_uuid.as_deref().ok_or_else(|| {
            InvalidParametersException("Relying Party UUID parameter must be set".to_string())
        })
    }

    pub fn get_relying_party_name(&self) -> Result<&str, Exception> {
        self.relying_party_name.as_deref().ok_or_else(|| {
            InvalidParametersException("Relying Party Name parameter must be set".to_string())
        })
    }

    pub fn get_network_interface(&self) -> Option<&str> {
        self.network_interface.as_deref()
    }

    pub fn get_allowed_interactions_order(&self) -> Option<&[String]> {
        self.allowed_interactions_order.as_deref()
    }

    pub fn validate_parameters(&self) -> Result<(), Exception> {
        if self.relying_party_uuid.is_none() {
            return Err(InvalidParametersException(
                "Relying Party UUID parameter must be set".to_string(),
            ));
        }

        if self.relying_party_name.is_none() {
            return Err(InvalidParametersException(
                "Relying Party Name parameter must be set".to_string(),
            ));
        }

        Ok(())
    }
}
