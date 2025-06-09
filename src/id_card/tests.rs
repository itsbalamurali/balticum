#[cfg(test)]
mod tests {
    use crate::id_card::IDCardClient; // Assuming IDCardClient is directly under id_card module

    #[test]
    fn test_id_card_client_new() {
        let _client = IDCardClient::new(); // Prefixed with _
        // Add assertions here if there are any properties to check on a new client.
        // For now, just ensuring it instantiates without panic.
        assert!(true); // Replace with actual assertions if applicable
    }
}
