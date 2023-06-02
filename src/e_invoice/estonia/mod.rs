use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use validator::Validate;
pub mod billberry;

#[derive(Serialize, Deserialize)]
#[serde(rename = "E_Invoice")]
pub struct EInvoice {
    #[serde(rename = "Header")]
    pub header: Header,

    pub invoice: Vec<Invoice>,

    #[serde(rename = "Footer")]
    pub footer: Footer,
}

#[derive(Serialize, Deserialize)]
pub struct Footer {
    #[serde(rename = "TotalNumberInvoices")]
    pub total_number_invoices: String,

    #[serde(rename = "TotalAmount")]
    pub total_amount: f32,
}

#[derive(Serialize, Deserialize)]
pub enum Test {
    #[serde(rename = "YES")]
    Yes,
    #[serde(rename = "NO")]
    No,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct Header {
    #[serde(rename = "SenderId")]
    pub sender_id: Option<String>,
    #[serde(rename = "ReceiverId")]
    pub receiver_id: Option<String>,
    #[serde(rename = "ContractId")]
    pub contract_id: Option<String>,
    #[serde(rename = "PayeeAccountNumber")]
    pub payee_account_number: Option<String>,
    #[serde(rename = "Test")]
    pub is_test: Test,
    #[serde(rename = "Date")]
    pub date: String,
    #[serde(rename = "FileId")]
    #[validate(length(min = 1))]
    pub file_id: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "AppId", skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "Invoice")]
pub struct Invoice {
    pub invoice_parties: InvoiceParties,

    #[serde(rename = "InvoiceInformation")]
    pub invoice_information: InvoiceInformation,

    #[serde(rename = "InvoiceSumGroup")]
    pub invoice_sum_group: InvoiceSumGroup,

    #[serde(rename = "InvoiceItem")]
    pub invoice_item: InvoiceItem,

    #[serde(rename = "PaymentInfo")]
    pub payment_info: PaymentInfo,

    #[serde(rename = "@invoiceId")]
    pub invoice_id: String,

    #[serde(rename = "@regNumber")]
    pub reg_number: String,

    #[serde(rename = "@sellerRegnumber")]
    pub seller_reg_number: String,

    #[serde(rename = "Attachment", skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Attachment>,
}

#[derive(Serialize, Deserialize)]
pub struct Attachment {
    #[serde(rename = "FileName")]
    pub file_name: String,
    #[serde(rename = "FileBase64")]
    pub file_base64: String,
}

#[derive(Serialize, Deserialize)]
pub struct InvoiceInformation {
    pub invoice_information_type: Type,

    #[serde(rename = "DocumentName")]
    pub document_name: String,

    #[serde(rename = "InvoiceNumber")]
    pub invoice_number: String,

    #[serde(
        rename = "PaymentReferenceNumber",
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_reference_number: Option<String>,

    #[serde(rename = "InvoiceDate")]
    pub invoice_date: String,

    #[serde(rename = "DueDate")]
    pub invoice_due_date: String,

    #[serde(rename = "FiteRatePerDay", skip_serializing_if = "Option::is_none")]
    pub late_fee_rate_per_day: Option<String>,

    #[serde(rename = "Period", skip_serializing_if = "Option::is_none")]
    pub period: Option<InvoicePeriod>,
}

#[derive(Serialize, Deserialize)]
pub struct InvoicePeriod {
    #[serde(rename = "StartDate")]
    pub start_date: String,

    #[serde(rename = "EndDate")]
    pub end_date: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "Type")]
pub struct Type {
    #[serde(rename = "@type")]
    pub type_type: InvoiceInformationType,
}

#[derive(Serialize, Deserialize)]
pub enum InvoiceInformationType {
    #[serde(rename = "DEB")]
    DEB,
    #[serde(rename = "CRE")]
    CRE,
}

#[derive(Serialize, Deserialize)]
pub struct InvoiceItem {
    pub invoice_item_groups: Vec<InvoiceItemGroup>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "InvoiceItemGroup")]
pub struct InvoiceItemGroup {
    #[serde(rename = "@groupId")]
    pub group_id: String,
    #[serde(rename = "ItemEntry")]
    pub item_entry: ItemEntry,
    #[serde(rename = "GroupEntry")]
    pub group_entry: GroupEntry,
}

#[derive(Serialize, Deserialize)]
pub struct GroupEntry {
    #[serde(rename = "GroupDescription")]
    pub description: String,
    #[serde(rename = "GroupSum")]
    pub sum: f32,
    #[serde(rename = "GroupTotal")]
    pub total: f32,
}

#[derive(Serialize, Deserialize)]
pub struct ItemEntry {
    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "Addition")]
    pub addition: InvoiceSumGroupAddition,

    pub item_detail_info: Vec<ItemDetailInfo>,

    #[serde(rename = "ItemTotal")]
    pub item_total: f32,

    #[serde(rename = "ItemSum")]
    pub item_sum: f32,

    #[serde(rename = "VAT")]
    pub vat: InvoiceSumGroupVat,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "ItemDetailInfo")]
pub struct ItemDetailInfo {
    #[serde(rename = "ItemUnit")]
    pub item_unit: String,
    #[serde(rename = "ItemAmount")]
    pub item_amount: f32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "InvoiceParties")]
pub struct InvoiceParties {
    #[serde(rename = "SellerParty")]
    pub seller_party: SellerParty,
    #[serde(rename = "BuyerParty")]
    pub buyer_party: BuyerParty,
    #[serde(rename = "DeliveryParty", skip_serializing_if = "Option::is_none")]
    pub delivery_party: Option<DeliveryParty>,
    #[serde(rename = "PayerParty", skip_serializing_if = "Option::is_none")]
    pub payer_party: Option<PayerParty>,
    #[serde(rename = "FactorParty", skip_serializing_if = "Option::is_none")]
    pub factor_party: Option<FactorParty>,
    #[serde(rename = "RecipientParty", skip_serializing_if = "Option::is_none")]
    pub recipient_party: Option<RecipientParty>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "BuyerParty")]
pub struct BuyerParty {
    #[serde(rename = "Name")]
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "RecipientParty")]
pub struct RecipientParty {
    #[serde(rename = "Name")]
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "DeliveryParty")]
pub struct DeliveryParty {
    #[serde(rename = "Name")]
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "PayerParty")]
pub struct PayerParty {
    #[serde(rename = "Name")]
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "FactorParty")]
pub struct FactorParty {
    #[serde(rename = "Name")]
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "SellerParty")]
pub struct SellerParty {
    #[serde(rename = "Name")]
    pub name: String,

    #[serde(rename = "RegNumber")]
    pub reg_number: String,

    #[serde(rename = "VATRegNumber")]
    vat_reg_number: String,

    #[serde(rename = "ContactData")]
    contact_data: ContactData,

    account_info: Vec<AccountInfo>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "AccountInfo")]
pub struct AccountInfo {
    #[serde(rename = "AccountNumber")]
    account_number: String,

    #[serde(rename = "IBAN")]
    iban: String,

    #[serde(rename = "BIC")]
    bic: String,

    #[serde(rename = "BankName")]
    bank_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct ContactData {
    #[serde(rename = "PhoneNumber")]
    phone_number: String,

    #[serde(rename = "E-mailAddress")]
    e_mail_address: String,

    #[serde(rename = "LegalAddress")]
    legal_address: LegalAddress,
}

#[derive(Serialize, Deserialize)]
pub struct LegalAddress {
    #[serde(rename = "PostalAddress1")]
    postal_address1: String,

    #[serde(rename = "City")]
    city: String,

    #[serde(rename = "PostalCode")]
    postal_code: String,

    #[serde(rename = "Country")]
    country: String,
}

#[derive(Serialize, Deserialize)]
pub struct InvoiceSumGroup {
    #[serde(rename = "TotalSum")]
    pub total_sum: f32,

    #[serde(rename = "Balance")]
    pub balance: Option<InvoiceSumGroupBalance>,

    #[serde(rename = "VAT")]
    pub vat: Option<InvoiceSumGroupVat>,

    #[serde(rename = "InvoiceSum")]
    pub invoice_sum: Option<f32>,

    #[serde(rename = "PenaltySum")]
    pub penalty_sum: Option<f32>,

    #[serde(rename = "Addition")]
    pub addition: Option<InvoiceSumGroupAddition>,

    #[serde(rename = "TotalToPay")]
    pub total_to_pay: Option<f32>,

    #[serde(rename = "Currency")]
    pub currency: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct InvoiceSumGroupVat {
    #[serde(rename = "VATRate")]
    pub vat_rate: f32,
    #[serde(rename = "VATSum")]
    pub vat_sum: f32,
}

#[derive(Serialize, Deserialize)]
pub struct InvoiceSumGroupBalance {
    #[serde(rename = "BalanceDate")]
    pub balance_date: NaiveDate,
    #[serde(rename = "BalanceEnd")]
    pub balance_end: f32,
}

#[derive(Serialize, Deserialize)]
pub struct InvoiceSumGroupAddition {
    #[serde(rename = "AddContent")]
    pub add_content: String,
    #[serde(rename = "AddSum")]
    pub add_sum: f32,
}

#[derive(Serialize, Deserialize)]
pub enum Payable {
    #[serde(rename = "YES")]
    Yes,
    #[serde(rename = "NO")]
    No,
}

#[derive(Serialize, Deserialize)]
pub struct PaymentInfo {
    #[serde(rename = "Currency")]
    pub currency: String,

    #[serde(rename = "PaymentDescription")]
    pub payment_description: String,

    #[serde(rename = "Payable")]
    pub payable: Payable,

    #[serde(rename = "PayDueDate")]
    pub pay_due_date: NaiveDate,

    #[serde(rename = "PaymentTotalSum")]
    pub payment_total_sum: f32,

    #[serde(rename = "PayerName")]
    pub payer_name: String,

    #[serde(rename = "PaymentId")]
    pub payment_id: String,

    #[serde(rename = "PayToAccount")]
    pub pay_to_account: String,

    #[serde(rename = "PayToName")]
    pub pay_to_name: String,
}
