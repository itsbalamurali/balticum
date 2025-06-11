use pkcs11::Ctx;
use pkcs11::types::{
    CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO, CKF_TOKEN_HW_TOKEN,
    CKF_TOKEN_REMOVABLE_DEVICE, CKF_TOKEN_TOKEN_INITIALIZED, CKF_USER_PIN_INITIALIZED,
    CkInitializeArgs, CK_SESSION_HANDLE, CK_FLAGS, CK_USER_TYPE, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_MECHANISM, CK_RV,
    CKA_CLASS, CKO_CERTIFICATE, CKO_PRIVATE_KEY, CKA_LABEL, CKA_ID, CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER,
    CK_ULONG
};
use pkcs11::errors::Error as Pkcs11Error;

const MAX_OBJECTS_TO_FIND_AT_ONCE: CK_ULONG = 10;

#[derive(Debug, thiserror::Error)]
pub enum IDCardError {
    #[error("PKCS#11 module initialization failed: {0}")]
    ModuleInitializationFailed(String),
    #[error("Failed to get slot list: {0}")]
    GetSlotListFailed(String),
    #[error("Failed to get slot info for slot ID {slot_id}: {error}")]
    GetSlotInfoFailed { slot_id: u64, error: String },
    #[error("Failed to get token info for slot ID {slot_id}: {error}")]
    GetTokenInfoFailed { slot_id: u64, error: String },
    #[error("Invalid PKCS#11 string data (not UTF-8 or padding error)")]
    InvalidStringData,
    #[error("Session open failed for slot ID {slot_id}: {error}")]
    SessionOpenFailed { slot_id: u64, error: String },
    #[error("Session close failed for handle {session_handle}: {error}")]
    SessionCloseFailed { session_handle: u64, error: String },
    #[error("Login failed for session handle {session_handle}: {error}")]
    LoginFailed { session_handle: u64, error: String },
    #[error("Logout failed for session handle {session_handle}: {error}")]
    LogoutFailed { session_handle: u64, error: String },
    #[error("PIN incorrect")]
    PinIncorrect,
    #[error("Find objects init failed for session handle {session_handle}: {error}")]
    FindObjectsInitFailed { session_handle: u64, error: String },
    #[error("Find objects failed for session handle {session_handle}: {error}")]
    FindObjectsFailed { session_handle: u64, error: String },
    #[error("Find objects final failed for session handle {session_handle}: {error}")]
    FindObjectsFinalFailed { session_handle: u64, error: String },
    #[error("Get attribute value failed for object handle {object_handle}, attribute type {attribute_type:#X}: {error}")]
    GetAttributeValueFailed { object_handle: u64, attribute_type: u64, error: String },
    #[error("Attribute not found for object handle {object_handle}, attribute type {attribute_type:#X}")]
    AttributeNotFound { object_handle: u64, attribute_type: u64 },
    #[error("Sign init failed for session handle {session_handle}, key handle {key_handle}: {error}")]
    SignInitFailed { session_handle: u64, key_handle: u64, error: String },
    #[error("Sign data failed for session handle {session_handle}, key handle {key_handle}: {error}")]
    SignFailed { session_handle: u64, key_handle: u64, error: String },
    #[error("Generic PKCS#11 library error: {0}")]
    Pkcs11LibError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Not implemented yet: {0}")]
    NotImplemented(String),
}

// Convert Pkcs11Error to IDCardError
impl From<Pkcs11Error> for IDCardError {
    fn from(err: Pkcs11Error) -> Self {
        IDCardError::Pkcs11LibError(err.to_string())
    }
}


#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub id: CK_SLOT_ID,
    pub description: String,
    pub manufacturer_id: String,
    pub hardware_version_major: u8,
    pub hardware_version_minor: u8,
    pub firmware_version_major: u8,
    pub firmware_version_minor: u8,
    pub is_removable: bool,
    pub is_hardware_device: bool,
}

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub serial_number: String,
    pub hardware_version_major: u8,
    pub hardware_version_minor: u8,
    pub firmware_version_major: u8,
    pub firmware_version_minor: u8,
    pub is_user_pin_initialized: bool,
    pub is_token_initialized: bool,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub handle: CK_OBJECT_HANDLE,
    pub label: Option<String>,
    pub id: Option<Vec<u8>>,
    pub subject: Option<Vec<u8>>,
    pub issuer: Option<Vec<u8>>,
    pub serial_number: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PrivateKeyInfo {
    pub handle: CK_OBJECT_HANDLE,
    pub label: Option<String>,
    pub id: Option<Vec<u8>>,
}

pub struct IDCardClient {
    pkcs11_ctx: Ctx,
}

fn pkcs11_bytes_to_string(bytes: &[u8]) -> Result<String, IDCardError> {
    let end = bytes.iter().rposition(|&b| b != b' ').map_or(bytes.len(), |p| p + 1);
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| IDCardError::InvalidStringData)
}

impl IDCardClient {
    pub fn new(pkcs11_module_path: &str) -> Result<Self, IDCardError> {
        let ctx = Ctx::new(pkcs11_module_path)
            .map_err(|e| IDCardError::ModuleInitializationFailed(e.to_string()))?;

        ctx.initialize(Some(CkInitializeArgs::library_cant_create_os_threads()))
            .map_err(|e| IDCardError::ModuleInitializationFailed(e.to_string()))?;

        Ok(Self { pkcs11_ctx: ctx })
    }

    pub fn list_slots(&self) -> Result<Vec<SlotInfo>, IDCardError> {
        let slot_ids = self.pkcs11_ctx.get_slot_list(true)
            .map_err(|e| IDCardError::GetSlotListFailed(e.to_string()))?;

        let mut slots_info = Vec::new();
        for slot_id in slot_ids {
            let pkcs11_slot_info: CK_SLOT_INFO = self.pkcs11_ctx.get_slot_info(slot_id)
                .map_err(|e| IDCardError::GetSlotInfoFailed { slot_id, error: e.to_string() })?;

            let slot_info = SlotInfo {
                id: slot_id,
                description: pkcs11_bytes_to_string(&pkcs11_slot_info.slotDescription)?,
                manufacturer_id: pkcs11_bytes_to_string(&pkcs11_slot_info.manufacturerID)?,
                hardware_version_major: pkcs11_slot_info.hardwareVersion.major,
                hardware_version_minor: pkcs11_slot_info.hardwareVersion.minor,
                firmware_version_major: pkcs11_slot_info.firmwareVersion.major,
                firmware_version_minor: pkcs11_slot_info.firmwareVersion.minor,
                is_removable: (pkcs11_slot_info.flags & CKF_TOKEN_REMOVABLE_DEVICE) != 0,
                is_hardware_device: (pkcs11_slot_info.flags & CKF_TOKEN_HW_TOKEN) != 0,
            };
            slots_info.push(slot_info);
        }
        Ok(slots_info)
    }

    pub fn get_token_info(&self, slot_id: CK_SLOT_ID) -> Result<TokenInfo, IDCardError> {
        let pkcs11_token_info: CK_TOKEN_INFO = self.pkcs11_ctx.get_token_info(slot_id)
            .map_err(|e| IDCardError::GetTokenInfoFailed { slot_id, error: e.to_string() })?;

        let token_info = TokenInfo {
            label: pkcs11_bytes_to_string(&pkcs11_token_info.label)?,
            manufacturer_id: pkcs11_bytes_to_string(&pkcs11_token_info.manufacturerID)?,
            model: pkcs11_bytes_to_string(&pkcs11_token_info.model)?,
            serial_number: pkcs11_bytes_to_string(&pkcs11_token_info.serialNumber)?,
            hardware_version_major: pkcs11_token_info.hardwareVersion.major,
            hardware_version_minor: pkcs11_token_info.hardwareVersion.minor,
            firmware_version_major: pkcs11_token_info.firmwareVersion.major,
            firmware_version_minor: pkcs11_token_info.firmwareVersion.minor,
            is_user_pin_initialized: (pkcs11_token_info.flags & CKF_USER_PIN_INITIALIZED) != 0,
            is_token_initialized: (pkcs11_token_info.flags & CKF_TOKEN_TOKEN_INITIALIZED) != 0,
        };
        Ok(token_info)
    }

    pub fn open_session(&self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Result<CK_SESSION_HANDLE, IDCardError> {
        self.pkcs11_ctx.open_session(slot_id, flags, None, None)
            .map_err(|e| IDCardError::SessionOpenFailed{ slot_id, error: e.to_string() })
    }

    pub fn close_session(&self, session_handle: CK_SESSION_HANDLE) -> Result<(), IDCardError> {
        self.pkcs11_ctx.close_session(session_handle)
            .map_err(|e| IDCardError::SessionCloseFailed{ session_handle, error: e.to_string() })
    }

    pub fn login(&self, session_handle: CK_SESSION_HANDLE, pin: &str) -> Result<(), IDCardError> {
        self.pkcs11_ctx.login(session_handle, CK_USER_TYPE_USER, Some(pin))
            .map_err(|e| {
                if let Pkcs11Error::Pkcs11(rv) = e {
                    if rv == CK_RV::CKR_PIN_INCORRECT {
                        return IDCardError::PinIncorrect;
                    }
                }
                IDCardError::LoginFailed{ session_handle, error: e.to_string()}
            })
    }

    pub fn logout(&self, session_handle: CK_SESSION_HANDLE) -> Result<(), IDCardError> {
        self.pkcs11_ctx.logout(session_handle)
            .map_err(|e| IDCardError::LogoutFailed{ session_handle, error: e.to_string() })
    }

    fn find_objects_by_template(&self, session_handle: CK_SESSION_HANDLE, template: &[CK_ATTRIBUTE]) -> Result<Vec<CK_OBJECT_HANDLE>, IDCardError> {
        self.pkcs11_ctx.find_objects_init(session_handle, template)
            .map_err(|e| IDCardError::FindObjectsInitFailed{ session_handle, error: e.to_string()})?;

        let mut object_handles = Vec::new();
        loop {
            let found_objects = self.pkcs11_ctx.find_objects(session_handle, MAX_OBJECTS_TO_FIND_AT_ONCE)
                .map_err(|e| IDCardError::FindObjectsFailed{ session_handle, error: e.to_string()})?;
            if found_objects.is_empty() {
                break;
            }
            object_handles.extend(found_objects);
        }

        self.pkcs11_ctx.find_objects_final(session_handle)
            .map_err(|e| IDCardError::FindObjectsFinalFailed{ session_handle, error: e.to_string()})?;

        Ok(object_handles)
    }

    pub fn get_attribute_value(&self, session_handle: CK_SESSION_HANDLE, object_handle: CK_OBJECT_HANDLE, attribute_type: CK_ATTRIBUTE_TYPE) -> Result<Option<Vec<u8>>, IDCardError> {
        let mut template = [CK_ATTRIBUTE::new(attribute_type)];
        match self.pkcs11_ctx.get_attribute_value(session_handle, object_handle, &mut template) {
            Ok(_) => {
                // CK_ATTRIBUTE::get_value() returns Option<Vec<u8>>.
                // It returns None if the attribute is not present, value is empty, or if ulValueLen is CK_UNAVAILABLE_INFORMATION.
                Ok(template[0].get_value())
            }
            Err(Pkcs11Error::Pkcs11(CK_RV::CKR_ATTRIBUTE_TYPE_INVALID)) => {
                 // This specific PKCS#11 error means the attribute type itself is not valid for the object,
                 // which is different from the attribute not being present.
                 // However, some tokens/implementations might return this if an attribute is simply not set.
                 // For simplicity, we can treat it as "not found" or a specific error.
                 // The prompt asks for AttributeNotFound.
                Err(IDCardError::AttributeNotFound { object_handle, attribute_type })
            }
            Err(Pkcs11Error::Pkcs11(CK_RV::CKR_ATTRIBUTE_SENSITIVE)) => {
                // Attribute is sensitive and cannot be revealed. Usually means Ok(None).
                Ok(None)
            }
            Err(e) => Err(IDCardError::GetAttributeValueFailed { object_handle, attribute_type, error: e.to_string() }),
        }
    }

    pub fn find_certificates(&self, session_handle: CK_SESSION_HANDLE, mut template: Vec<CK_ATTRIBUTE>) -> Result<Vec<CertificateInfo>, IDCardError> {
        let class_cert = CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_CERTIFICATE);
        template.push(class_cert);

        let object_handles = self.find_objects_by_template(session_handle, &template)?;
        let mut certificates = Vec::new();

        for handle in object_handles {
            let label_bytes = self.get_attribute_value(session_handle, handle, CKA_LABEL)?;
            let id_bytes = self.get_attribute_value(session_handle, handle, CKA_ID)?;
            let subject_bytes = self.get_attribute_value(session_handle, handle, CKA_SUBJECT)?;
            let issuer_bytes = self.get_attribute_value(session_handle, handle, CKA_ISSUER)?;
            let serial_bytes = self.get_attribute_value(session_handle, handle, CKA_SERIAL_NUMBER)?;

            certificates.push(CertificateInfo {
                handle,
                label: label_bytes.and_then(|b| pkcs11_bytes_to_string(&b).ok()),
                id: id_bytes,
                subject: subject_bytes,
                issuer: issuer_bytes,
                serial_number: serial_bytes,
            });
        }
        Ok(certificates)
    }

    pub fn find_private_keys(&self, session_handle: CK_SESSION_HANDLE, mut template: Vec<CK_ATTRIBUTE>) -> Result<Vec<PrivateKeyInfo>, IDCardError> {
        let class_private_key = CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_PRIVATE_KEY);
        template.push(class_private_key);

        let object_handles = self.find_objects_by_template(session_handle, &template)?;
        let mut private_keys = Vec::new();

        for handle in object_handles {
            let label_bytes = self.get_attribute_value(session_handle, handle, CKA_LABEL)?;
            let id_bytes = self.get_attribute_value(session_handle, handle, CKA_ID)?;

            private_keys.push(PrivateKeyInfo {
                handle,
                label: label_bytes.and_then(|b| pkcs11_bytes_to_string(&b).ok()),
                id: id_bytes,
            });
        }
        Ok(private_keys)
    }

    pub fn sign_data(&self, session_handle: CK_SESSION_HANDLE, mechanism: &CK_MECHANISM, key_handle: CK_OBJECT_HANDLE, data: &[u8]) -> Result<Vec<u8>, IDCardError> {
        self.pkcs11_ctx.sign_init(session_handle, mechanism, key_handle)
            .map_err(|e| IDCardError::SignInitFailed { session_handle, key_handle, error: e.to_string() })?;

        self.pkcs11_ctx.sign(session_handle, data)
            .map_err(|e| IDCardError::SignFailed { session_handle, key_handle, error: e.to_string() })
    }
}

#[cfg(test)]
mod tests;
