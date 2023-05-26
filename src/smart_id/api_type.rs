use std::fmt::Display;

pub enum ApiType {
    Authentication,
}

impl Display for ApiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let api_type = match self {
            ApiType::Authentication => "authentication",
        };
        write!(f, "{}", api_type)
    }
}