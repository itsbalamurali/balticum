use reqwest::header::HeaderMap;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use crate::e_invoice::estonia::EInvoice;

pub struct BillBerryApiClient {
    api_id: String,
    api_key: String,
    api_url: String,
}

impl BillBerryApiClient {
    pub fn new(api_id: String, api_key: String) -> Self {
        Self {
            api_id,
            api_key,
            api_url: "https://api.billberry.ee".to_string(),
        }
    }

    pub async fn get_e_invoice(&self, invoice_id: &str) -> Result<BillBerryReceivedInvoice,reqwest::Error> {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/vnd.billberry.invoice+json; v=1".parse().unwrap());
        let resp = self.http_get(&format!("{}/invoices/{}", self.api_url, invoice_id),headers).await.unwrap();
        resp.json().await
    }

    pub async fn get_e_invoice_xml(&self, invoice_id: &str) -> EInvoice {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/xml".parse().unwrap());
        let resp = self.http_get(&format!("{}/invoices/{}.xml", self.api_url, invoice_id),headers).await.unwrap();
        quick_xml::de::from_str::<EInvoice>(&resp.text().await.unwrap()).unwrap()
    }

    pub async fn get_received_e_invoices(&self) -> Result<Vec<BillBerryReceivedInvoice>,reqwest::Error>  {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/vnd.billberry.invoice+json; v=1".parse().unwrap());
        let resp = self.http_get(&format!("{}/invoices/received", self.api_url),headers).await.unwrap();
        resp.json::<Vec<BillBerryReceivedInvoice>>().await
    }

    pub async fn send_e_invoice(&self, invoice: &EInvoice, send_immediately: bool) -> Result<BillBerryInvoiceSentResponse,reqwest::Error> {
        let request = quick_xml::se::to_string(invoice).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/vnd.billberry.invoice+json; v=1".parse().unwrap());
        headers.insert("Content-Type", "application/xml".parse().unwrap());
        if send_immediately {
            headers.insert("X-Send", "immediately".parse().unwrap());
        }
        self.http_post::<BillBerryInvoiceSentResponse>(&format!("{}/invoices", self.api_url),request,headers).await
    }

    async fn http_get(&self, url: &str, headers: HeaderMap) -> Result<Response,reqwest::Error> {
        reqwest::Client::new()
            .get(url)
            .headers(headers)
            .basic_auth(self.api_id.clone(), Some(self.api_key.clone()))
            .send().await
    }

    async fn http_post<R>(&self, url: &str, body: String, headers: HeaderMap) -> Result<R,reqwest::Error> where R: DeserializeOwned {
        let response = reqwest::Client::new()
            .post(url)
            .headers(headers)
            .body(body)
            .basic_auth(self.api_id.clone(), Some(self.api_key.clone())).send().await.unwrap();
        let json = response.json::<R>().await.unwrap();
        Ok(json)
    }
}



#[derive(Serialize, Deserialize)]
pub struct BillBerryReceivedInvoice {
    pub id: i64,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "registryCode")]
    pub registry_code: String,
    #[serde(rename = "senderRegistryCode")]
    pub sender_registry_code: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "receiverRegistryCode")]
    pub receiver_registry_code: String,
    #[serde(rename = "receiverName")]
    pub receiver_name: String,
    pub number: String,
    pub date: String,
    #[serde(rename = "dueDate")]
    pub due_date: String,
    #[serde(rename = "receivedAt")]
    pub received_at: Option<String>,
    #[serde(rename = "receivedFromOperator")]
    pub received_from_operator: Option<String>,
    #[serde(rename = "receivedFileId")]
    pub received_file_id: Option<String>,
    #[serde(rename = "receivedExternalId")]
    pub received_external_id: Option<String>,
    #[serde(rename = "sentAt")]
    pub sent_at: String,
    #[serde(rename = "sentToOperator")]
    pub sent_to_operator: String,
    #[serde(rename = "sentFileId")]
    pub sent_file_id: String,
    #[serde(rename = "sentExternalId")]
    pub sent_external_id: String,
    #[serde(rename = "pdfSize")]
    pub pdf_size: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BillBerryInvoiceSentResponse {
    pub id: i64,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "registryCode")]
    pub registry_code: String,
    #[serde(rename = "senderRegistryCode")]
    pub sender_registry_code: String,
    #[serde(rename = "senderName")]
    pub sender_name: String,
    #[serde(rename = "receiverRegistryCode")]
    pub receiver_registry_code: String,
    #[serde(rename = "receiverName")]
    pub receiver_name: String,
    pub number: String,
    pub date: String,
    #[serde(rename = "dueDate")]
    pub due_date: String,
    #[serde(rename = "receivedAt")]
    pub received_at: Option<String>,
    #[serde(rename = "receivedFromOperator")]
    pub received_from_operator: Option<String>,
    #[serde(rename = "receivedFileId")]
    pub received_file_id: Option<String>,
    #[serde(rename = "receivedExternalId")]
    pub received_external_id: Option<String>,
    #[serde(rename = "sentAt")]
    pub sent_at: String,
    #[serde(rename = "sentToOperator")]
    pub sent_to_operator: String,
    #[serde(rename = "sentFileId")]
    pub sent_file_id: String,
    #[serde(rename = "sentExternalId")]
    pub sent_external_id: String,
}