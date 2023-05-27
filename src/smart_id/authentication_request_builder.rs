use crate::smart_id::exceptions::Exception;
use crate::smart_id::exceptions::Exception::{InvalidParametersException, TechnicalErrorException};
use crate::smart_id::models::{AuthenticationHash, AuthenticationSessionRequest, AuthenticationSessionResponse, HashType, Interaction, SemanticsIdentifier, SessionStatus, SignableData, SmartIdAuthenticationResponse};
use crate::smart_id::session_status_poller::SessionStatusPoller;
use crate::smart_id::smart_id_rest_connector::SmartIdRestConnector;

pub struct AuthenticationRequestBuilder {
    pub semantics_identifier: Option<SemanticsIdentifier>,
    pub document_number: Option<String>,
    pub certificate_level: Option<String>,
    pub data_to_sign: Option<SignableData>,
    pub authentication_hash: Option<AuthenticationHash>,
    pub allowed_interactions_order: Vec<Interaction>,
    pub nonce: Option<String>,
    pub endpoint_url : String,
}

impl<'a> AuthenticationRequestBuilder {
    pub fn new(endpoint_url: String)-> AuthenticationRequestBuilder {
        AuthenticationRequestBuilder{
            semantics_identifier: None,
            document_number: None,
            certificate_level: None,
            data_to_sign: None,
            authentication_hash: None,
            allowed_interactions_order: Vec::new(),
            nonce: None,
            endpoint_url:endpoint_url.to_owned(),
            //connector: &mut SmartIdRestConnector::new(endpoint_url),
        }
    }

    pub fn with_document_number(mut self, document_number: String) -> Self {
        self.document_number = Some(document_number);
        self
    }

    pub fn with_semantics_identifier(mut self, semantics_identifier: SemanticsIdentifier) -> Self {
        self.semantics_identifier = Some(semantics_identifier);
        self
    }

    pub fn with_semantics_identifier_as_string(
        mut self,
        semantics_identifier_as_string: String,
    ) -> Self {
        self.semantics_identifier = Some(SemanticsIdentifier::from_string(
            semantics_identifier_as_string,
        ));
        self
    }

    pub fn with_signable_data(mut self, data_to_sign: SignableData) -> Self {
        self.data_to_sign = Some(data_to_sign);
        self
    }

    pub fn with_authentication_hash(mut self, authentication_hash: AuthenticationHash) -> Self {
        self.authentication_hash = Some(authentication_hash);
        self
    }

    pub fn with_certificate_level(mut self, certificate_level: String) -> Self {
        self.certificate_level = Some(certificate_level);
        self
    }

    pub fn with_allowed_interactions_order(
        mut self,
        allowed_interactions_order: Vec<Interaction>,
    ) -> Self {
        self.allowed_interactions_order = allowed_interactions_order;
        self
    }

    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.nonce = Some(nonce);
        self
    }

    // pub fn with_relying_party_uuid(&mut self, relying_party_uuid: String) -> &mut AuthenticationRequestBuilder<'a> {
    //     self.connector.with_relying_party_uuid(relying_party_uuid.as_str());
    //     self
    // }
    //
    // pub fn with_relying_party_name(&mut self, relying_party_name: String) -> &mut AuthenticationRequestBuilder<'a> {
    //     self.connector.with_relying_party_name(relying_party_name.as_str());
    //     self
    // }

    pub async fn authenticate(
        &self,
    ) -> Result<SmartIdAuthenticationResponse, Box<dyn std::error::Error>> {
        let mut session_status_poller = SessionStatusPoller::new(self.endpoint_url.clone());
        session_status_poller.set_polling_sleep_timeout_ms(1000);
        session_status_poller.set_session_status_response_socket_timeout_ms(
            1000,
        );
        let response = self.get_authentication_response().await.unwrap();
        let session_id = response.session_id;
        let session_status = session_status_poller
            .fetch_final_session_status(session_id)
            .await
            .unwrap()
            .unwrap();
        self.validate_session_status(&session_status).unwrap();
        Ok(self.create_smart_id_authentication_response(session_status))
    }

    pub async fn start_authentication_and_return_session_id(
        &self,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = self.get_authentication_response().await.unwrap();
        Ok(response.session_id)
    }

    fn create_authentication_session_request(&self,relying_party_uuid: &str, relying_party_name: &str) -> AuthenticationSessionRequest {
        let mut request = AuthenticationSessionRequest::new();
        request.set_relying_party_uuid(relying_party_uuid);
        request.set_relying_party_name(relying_party_name);
        request.set_certificate_level(self.certificate_level.to_owned().unwrap());
        request.set_hash_type(self.get_hash_type());
        request.set_hash(self.get_hash_in_base64().as_str());
        request.set_allowed_interactions_order((*self.allowed_interactions_order).to_vec());
        request.set_nonce(self.nonce.clone().unwrap());
        // request.set_network_interface(self.connector.get_network_interface());
        request
    }

    fn get_hash_type(&self) -> HashType {
        if let Some(hash_type) = &self.authentication_hash {
            return hash_type.hash_type.clone();
        } else if let Some(data_to_sign) = &self.data_to_sign {
            return data_to_sign.hash_type.clone();
        }
        HashType::Sha512
    }

    fn get_hash_type_string(&self) -> String {
        if let Some(hash_type) = &self.authentication_hash {
            return hash_type.hash_type.to_string();
        } else if let Some(data_to_sign) = &self.data_to_sign {
            return data_to_sign.hash_type.to_string();
        }
        String::new()
    }

    fn get_hash_in_base64(&self) -> String {
        if let Some(authentication_hash) = &self.authentication_hash {
            return authentication_hash.calculate_hash_in_base64();
        } else if let Some(data_to_sign) = &self.data_to_sign {
            return data_to_sign.calculate_hash_in_base64();
        }
        String::new()
    }

    async fn get_authentication_response(
        &self,
    ) -> Result<AuthenticationSessionResponse, Exception> {
        self.validate_parameters()?;
        //TODO: fix relying party params
        let request = self.create_authentication_session_request("","");
        let connector = SmartIdRestConnector::new(self.endpoint_url.clone());
        if let Some(document_number) = &self.document_number {
            Ok(
                connector
                .authenticate(document_number.to_string(), request)
                .await
                .unwrap())
        } else if let Some(semantics_identifier) = &self.semantics_identifier {
            Ok(connector
                .authenticate_with_semantics_identifier(semantics_identifier, request)
                .await
                .unwrap())
        } else {
            Err(InvalidParametersException(
                "Either document number or semantics identifier must be set".to_string(),
            ))
        }
    }

    fn validate_parameters(&self) -> Result<(), Exception> {
        if self.document_number.is_none() && self.semantics_identifier.is_none() {
            return Err(InvalidParametersException(
                "Either document number or semantics identifier must be set".to_string(),
            ));
        }

        self.validate_semantics_identifier_if_set().unwrap();

        if !self.is_signable_data_set() && !self.is_authentication_hash_set() {
            return Err(InvalidParametersException(
                "Signable data or hash with hash type must be set".to_string(),
            ));
        }

        self.verify_interactions_if_set().unwrap();

        Ok(())
    }

    fn is_signable_data_set(&self) -> bool {
        self.data_to_sign.is_some()
    }

    fn is_authentication_hash_set(&self) -> bool {
        self.authentication_hash.is_some()
    }

    fn validate_session_status(&self, session_status: &SessionStatus) -> Result<(), Exception> {
        if session_status.signature.is_none() {
            return Err(TechnicalErrorException(
                "Signature was not present in the response".to_string(),
            ));
        }
        if session_status.cert.is_none() {
            return Err(TechnicalErrorException(
                "Certificate was not present in the response".to_string(),
            ));
        }
        Ok(())
    }

    fn create_smart_id_authentication_response(
        &self,
        session_status: SessionStatus,
    ) -> SmartIdAuthenticationResponse {
        let session_result = session_status.result.unwrap();
        let session_signature = session_status.signature.unwrap();
        let session_certificate = session_status.cert.unwrap();

        let mut authentication_response = SmartIdAuthenticationResponse::new();
        authentication_response.set_end_result(session_result.end_result.clone());
        authentication_response.set_signed_data(self.get_data_to_sign());
        authentication_response.set_ignored_properties(session_status.ignored_properties.clone());
        authentication_response
            .set_interaction_flow_used(session_status.interaction_flow_used.clone());
        authentication_response.set_value_in_base64(session_signature.value.unwrap());
        authentication_response.set_algorithm_name(session_signature.algorithm.unwrap());
        authentication_response.set_certificate(session_certificate.value.unwrap());
        authentication_response
            .set_certificate_level(session_certificate.certificate_level.unwrap());
        authentication_response.set_document_number(session_result.document_number.clone());
        authentication_response
    }

    fn get_data_to_sign(&self) -> String {
        if let Some(authentication_hash) = &self.authentication_hash {
            authentication_hash.data_to_sign.clone()
        } else if let Some(data_to_sign) = &self.data_to_sign {
            data_to_sign.data_to_sign.clone()
        } else {
            String::new()
        }
    }

    pub fn get_semantics_identifier(&self) -> &SemanticsIdentifier {
        &self.semantics_identifier.as_ref().unwrap()
    }

    fn validate_semantics_identifier_if_set(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(semantics_identifier) = &self.semantics_identifier {
            semantics_identifier.validate()?;
        }
        Ok(())
    }

    fn verify_interactions_if_set(&self) -> Result<(), Box<dyn std::error::Error>> {
        let interactions_order= &self.allowed_interactions_order;
            for interaction in interactions_order {
                //TODO: validate interaction
                //interaction.validate()?;
            }
        Ok(())
    }
}
