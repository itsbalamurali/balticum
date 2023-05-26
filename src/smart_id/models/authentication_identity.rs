
pub struct AuthenticationIdentity {
    pub given_name: String,
    pub sur_name: String,
    pub identity_code: String,
    pub identity_number: String,
    pub country: String,
    pub auth_certificate: String,
    pub date_of_birth: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuthenticationIdentity {
    pub fn new() -> AuthenticationIdentity {
        AuthenticationIdentity {
            given_name: String::new(),
            sur_name: String::new(),
            identity_code: String::new(),
            identity_number: String::new(),
            country: String::new(),
            auth_certificate: String::new(),
            date_of_birth: None,
        }
    }

    pub fn set_given_name(&mut self, given_name: String) -> &mut AuthenticationIdentity {
        self.given_name = given_name;
        self
    }

    pub fn get_given_name(&self) -> &str {
        &self.given_name
    }

    pub fn set_sur_name(&mut self, sur_name: String) -> &mut AuthenticationIdentity {
        self.sur_name = sur_name;
        self
    }

    pub fn get_sur_name(&self) -> &str {
        &self.sur_name
    }

    pub fn set_identity_code(&mut self, identity_code: String) -> &mut AuthenticationIdentity {
        self.identity_code = identity_code;
        self
    }

    pub fn get_identity_code(&self) -> &str {
        &self.identity_code
    }

    pub fn set_identity_number(&mut self, identity_number: String) -> &mut AuthenticationIdentity {
        self.identity_number = identity_number;
        self
    }

    pub fn get_identity_number(&self) -> &str {
        &self.identity_number
    }

    pub fn set_country(&mut self, country: String) -> &mut AuthenticationIdentity {
        self.country = country;
        self
    }

    pub fn get_country(&self) -> &str {
        &self.country
    }

    pub fn set_auth_certificate(&mut self, auth_certificate: String) -> &mut AuthenticationIdentity {
        self.auth_certificate = auth_certificate;
        self
    }

    pub fn get_auth_certificate(&self) -> &str {
        &self.auth_certificate
    }

    pub fn set_date_of_birth(&mut self, date_of_birth: Option<chrono::DateTime<chrono::Utc>>) -> &mut AuthenticationIdentity {
        self.date_of_birth = date_of_birth;
        self
    }

    pub fn get_date_of_birth(&self) -> Option<&chrono::DateTime<chrono::Utc>> {
        self.date_of_birth.as_ref()
    }
}
