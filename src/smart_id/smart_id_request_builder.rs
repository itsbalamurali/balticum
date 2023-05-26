use crate::smart_id::exceptions::Exception;
use crate::smart_id::exceptions::Exception::InvalidParametersException;
use crate::smart_id::session_status_poller::SessionStatusPoller;
use crate::smart_id::smart_id_rest_connector::SmartIdRestConnector;

pub struct SmartIdRequestBuilder<'a> {
    connector: &'a SmartIdRestConnector<'a>,
    session_status_poller: SessionStatusPoller<'a>,
    relying_party_uuid: Option<String>,
    relying_party_name: Option<String>,
    network_interface: Option<String>,
    allowed_interactions_order: Option<Vec<String>>,
}

impl SmartIdRequestBuilder<'_> {
    pub fn new(connector: &SmartIdRestConnector, session_status_poller: SessionStatusPoller) -> Self {
        SmartIdRequestBuilder {
            connector,
            session_status_poller,
            relying_party_uuid: None,
            relying_party_name: None,
            network_interface: None,
            allowed_interactions_order: None,
        }
    }

    pub fn with_relying_party_uuid(mut self, relying_party_uuid: String) -> Self {
        self.relying_party_uuid = Some(relying_party_uuid);
        self
    }

    pub fn with_relying_party_name(mut self, relying_party_name: String) -> Self {
        self.relying_party_name = Some(relying_party_name);
        self
    }

    pub fn with_network_interface(mut self, network_interface: String) -> Self {
        self.network_interface = Some(network_interface);
        self
    }

    pub fn get_connector(&self) -> &SmartIdRestConnector {
        &self.connector
    }

    pub fn get_session_status_poller(&mut self) -> &mut SessionStatusPoller {
        let network_interface = self.get_network_interface().or_else(||Some("")).unwrap();
        self.session_status_poller
            .with_network_interface(network_interface.to_string())
    }

    pub fn get_relying_party_uuid(&self) -> Result<&str, Exception> {
        self.relying_party_uuid
            .as_deref()
            .ok_or_else(|| InvalidParametersException("Relying Party UUID parameter must be set".to_string()))
    }

    pub fn get_relying_party_name(&self) -> Result<&str, Exception> {
        self.relying_party_name
            .as_deref()
            .ok_or_else(|| InvalidParametersException("Relying Party Name parameter must be set".to_string()))
    }

    pub fn get_network_interface(&self) -> Option<&str> {
        self.network_interface.as_deref()
    }

    pub fn get_allowed_interactions_order(&self) -> Option<&[String]> {
        self.allowed_interactions_order.as_deref()
    }

    pub fn validate_parameters(&self) -> Result<(), Exception> {
        if self.relying_party_uuid.is_none() {
            return Err(InvalidParametersException("Relying Party UUID parameter must be set".to_string()));
        }

        if self.relying_party_name.is_none() {
            return Err(InvalidParametersException("Relying Party Name parameter must be set".to_string()));
        }

        Ok(())
    }
}
