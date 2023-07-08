use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::{fs, io, str};
use zip::ZipArchive;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "ettevotja_rekvisiidid__yldandmed.xml";
    let csv = File::create("subscribers.csv").unwrap();
    //Check if the file exists
    match fs::metadata(file_path) {
        Ok(_) => {
            //Open the file
            let xml = File::open(file_path).unwrap();
            process_file(BufReader::new(xml), BufWriter::new(csv)).await
        }
        Err(_) => {
            //Download the date from ariregister.rik.ee
            let data_zip_url = "https://avaandmed.ariregister.rik.ee/sites/default/files/avaandmed/ettevotja_rekvisiidid__yldandmed.xml.zip";
            //Download the zip file
            let resp = reqwest::get(data_zip_url)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            //Create a file to store the zip
            let mut zip = File::create(file_path).unwrap();
            //Write the zip to the file
            io::copy(&mut resp.as_ref(), &mut zip).unwrap();
            let mut ziparchive = ZipArchive::new(zip).unwrap();
            let mut zipfile = ziparchive.by_index(0).unwrap();
            let mut xml = File::create(file_path.trim_end_matches(".zip")).unwrap();
            io::copy(&mut zipfile, &mut xml).unwrap();
            // Read the file within the zip
            process_file(BufReader::new(xml), BufWriter::new(csv)).await
        }
    }
}

async fn process_file(
    mut buf: BufReader<File>,
    mut csv: BufWriter<File>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut line = String::new();
    let mut xml_data = String::new();
    let mut csv_writer = csv::Writer::from_writer(csv);
    csv_writer.write_record(&["COMPANYNAME", "REGISTRYCODE", "EMAIL"])?;
    // Read the file line by line
    while buf.read_line(&mut line).unwrap() > 0 {
        if line == "<?xml version='1.0' encoding='UTF-8'?>\n".to_string()
            || line == "<ettevotjad>\n".to_string()
            || line == "</ettevotjad>\n".to_string()
        {
            line.clear();
            continue;
        }
        xml_data.push_str(&line);
        line.clear();
        // Process the XML data if a complete JSON object is available
        if xml_data.ends_with("</ettevotja>\n") {
            // Parse the XML data
            let data: Ettevotja = quick_xml::de::from_str(&xml_data).unwrap();
            let mut subscriber: HashMap<String, String> = HashMap::new();
            println!("Company: {}", data.nimi);
            subscriber.insert("COMPANYNAME".to_string(), data.nimi.to_owned());
            subscriber.insert("REGISTRYCODE".to_string(), data.ariregistri_kood);
            let mut email = String::new();
            let sidevahendid = data.yldandmed.sidevahendid;
            match sidevahendid {
                Some(sidevahendid) => {
                    for address in sidevahendid.item {
                        if address.liik.unwrap() == "EMAIL" {
                            email = address
                                .sisu
                                .unwrap()
                                .trim_end_matches(".")
                                .to_string()
                                .replace("@.", "@")
                                .replace("..", ".")
                                .replace("ö", "o")
                                .replace("ō", "o")
                                .replace("\"@", "")
                                .replace("ä", "a")
                                .replace(" ", "")
                                .replace(">", "");
                            if !email.contains(" ") {
                                subscriber.insert("EMAIL".to_string(), email.to_owned());
                            }
                        }
                    }
                    if subscriber.get("EMAIL").is_none() {
                        println!("No email for {}", data.nimi.to_owned());
                        email.clear();
                        xml_data.clear();
                        continue;
                    }
                }
                None => {
                    println!("No sidevahendid for {}", data.nimi.to_owned());
                    email.clear();
                    xml_data.clear();
                    continue;
                }
            }

            csv_writer.write_record(&[
                subscriber.get("COMPANYNAME").unwrap(),
                subscriber.get("REGISTRYCODE").unwrap(),
                subscriber.get("EMAIL").unwrap(),
            ])?;

            // let existing_sub = reqwest::Client::new()
            //     .get(format!("https://emails.mydatamyconsent.com/api/lists/zf398oodn9829/subscribers/search-by-email?EMAIL={}",email))
            //     .header("X-Api-Key", "6f45cea56539636598af3aa00a7043bab641844f")
            //     .send().await?;
            // if !existing_sub.status().is_success() {
            //     println!("Email: {}", email);
            //     println!("{}",existing_sub.text().await?);
            //     let resp = reqwest::Client::new()
            //         .post("https://emails.mydatamyconsent.com/api/lists/zf398oodn9829/subscribers")
            //         .header("X-Api-Key", "6f45cea56539636598af3aa00a7043bab641844f")
            //         .form(&subscriber).send().await?;
            //     if !resp.status().is_success() {
            //         println!("Error: {}", resp.text().await?);
            //         email.clear();
            //         xml_data.clear();
            //         continue;
            //     }
            // }

            // Reset for the next object
            email.clear();
            xml_data.clear();
        }
    }
    csv_writer.flush()?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "ettevotja")]
pub struct Ettevotja {
    #[serde(rename = "ariregistri_kood")]
    ariregistri_kood: String,

    #[serde(rename = "nimi")]
    nimi: String,

    #[serde(rename = "yldandmed")]
    yldandmed: Yldandmed,
}

#[derive(Serialize, Deserialize)]
pub struct Yldandmed {
    // #[serde(rename = "ettevotteregistri_nr")]
    // ettevotteregistri_nr: String,
    //
    // #[serde(rename = "esmaregistreerimise_kpv")]
    // esmaregistreerimise_kpv: String,
    //
    // #[serde(rename = "kustutamise_kpv")]
    // kustutamise_kpv: String,
    //
    // #[serde(rename = "staatus")]
    // staatus: String,
    //
    // #[serde(rename = "staatus_tekstina")]
    // staatus_tekstina: String,
    //
    // #[serde(rename = "piirkond")]
    // piirkond: String,
    //
    // #[serde(rename = "piirkond_tekstina")]
    // piirkond_tekstina: String,
    //
    // #[serde(rename = "piirkond_tekstina_pikk")]
    // piirkond_tekstina_pikk: String,
    //
    // #[serde(rename = "evks_registreeritud")]
    // evks_registreeritud: String,
    //
    // #[serde(rename = "evks_registreeritud_kande_kpv")]
    // evks_registreeritud_kande_kpv: String,
    //
    // #[serde(rename = "oiguslik_vorm")]
    // oiguslik_vorm: String,
    //
    // #[serde(rename = "oiguslik_vorm_nr")]
    // oiguslik_vorm_nr: String,
    //
    // #[serde(rename = "oiguslik_vorm_tekstina")]
    // oiguslik_vorm_tekstina: String,
    //
    // #[serde(rename = "oigusliku_vormi_alaliik")]
    // oigusliku_vormi_alaliik: String,
    //
    // #[serde(rename = "lahknevusteade_puudumisest")]
    // lahknevusteade_puudumisest: String,
    //
    // #[serde(rename = "oigusliku_vormi_alaliik_tekstina")]
    // oigusliku_vormi_alaliik_tekstina: String,
    //
    // #[serde(rename = "asutatud_sissemakset_tegemata")]
    // asutatud_sissemakset_tegemata: String,
    //
    // #[serde(rename = "loobunud_vorminouetest")]
    // loobunud_vorminouetest: String,
    //
    // #[serde(rename = "on_raamatupidamiskohustuslane")]
    // on_raamatupidamiskohustuslane: String,
    //
    // #[serde(rename = "tegutseb")]
    // tegutseb: String,
    //
    // #[serde(rename = "tegutseb_tekstina")]
    // tegutseb_tekstina: String,
    //
    // #[serde(rename = "staatused")]
    // staatused: Staatused,
    //
    // #[serde(rename = "arinimed")]
    // arinimed: Arinimed,
    //
    // #[serde(rename = "aadressid")]
    // aadressid: Aadressid,
    //
    // #[serde(rename = "kontaktisiku_aadressid", skip_serializing_if = "Option::is_none")]
    // kontaktisiku_aadressid: Option<Aadressid>,
    //
    // #[serde(rename = "oiguslikud_vormid")]
    // oiguslikud_vormid: Arinimed,
    //
    // #[serde(rename = "kapitalid")]
    // kapitalid: Kapitalid,
    //
    // #[serde(rename = "majandusaastad")]
    // majandusaastad: Arinimed,
    //
    // #[serde(rename = "pohikirjad")]
    // pohikirjad: Pohikirjad,
    //
    // #[serde(rename = "markused_kaardil")]
    // markused_kaardil: MarkusedKaardil,
    #[serde(rename = "sidevahendid")]
    sidevahendid: Option<Sidevahendid>,
}

#[derive(Serialize, Deserialize)]
pub struct Sidevahendid {
    pub item: Vec<Arinimed>,
}
//
// #[derive(Serialize, Deserialize)]
// pub struct Aadressid {
//     item: AadressidItem,
// }

// #[derive(Serialize, Deserialize)]
// #[serde(rename = "item")]
// pub struct AadressidItem {
//     #[serde(rename = "kirje_id")]
//     kirje_id: String,
//
//     #[serde(rename = "kaardi_piirkond")]
//     kaardi_piirkond: String,
//
//     #[serde(rename = "kaardi_nr")]
//     kaardi_nr: String,
//
//     #[serde(rename = "kaardi_tyyp")]
//     kaardi_tyyp: String,
//
//     #[serde(rename = "kande_nr")]
//     kande_nr: String,
//
//     #[serde(rename = "riik")]
//     riik: String,
//
//     #[serde(rename = "riik_tekstina")]
//     riik_tekstina: String,
//
//     #[serde(rename = "ehak")]
//     ehak: String,
//
//     #[serde(rename = "ehak_nimetus")]
//     ehak_nimetus: String,
//
//     #[serde(rename = "tanav_maja_korter")]
//     tanav_maja_korter: String,
//
//     #[serde(rename = "aadress_ads__ads_oid")]
//     aadress_ads_ads_oid: String,
//
//     #[serde(rename = "aadress_ads__adr_id")]
//     aadress_ads_adr_id: String,
//
//     #[serde(rename = "aadress_ads__ads_normaliseeritud_taisaadress")]
//     aadress_ads_ads_normaliseeritud_taisaadress: String,
//
//     #[serde(rename = "aadress_ads__ads_normaliseeritud_taisaadress_tapsustus")]
//     aadress_ads_ads_normaliseeritud_taisaadress_tapsustus: String,
//
//     #[serde(rename = "aadress_ads__koodaadress")]
//     aadress_ads_koodaadress: String,
//
//     #[serde(rename = "aadress_ads__adob_id")]
//     aadress_ads_adob_id: String,
//
//     #[serde(rename = "aadress_ads__tyyp")]
//     aadress_ads_tyyp: String,
//
//     #[serde(rename = "postiindeks")]
//     postiindeks: String,
//
//     #[serde(rename = "algus_kpv")]
//     algus_kpv: String,
//
//     #[serde(rename = "lopp_kpv")]
//     lopp_kpv: String,
// }
//
//
#[derive(Serialize, Deserialize)]
pub struct Arinimed {
    #[serde(rename = "kirje_id")]
    kirje_id: String,

    #[serde(rename = "kaardi_piirkond")]
    kaardi_piirkond: String,

    #[serde(rename = "kaardi_nr")]
    kaardi_nr: String,

    #[serde(rename = "kaardi_tyyp")]
    kaardi_tyyp: String,

    #[serde(rename = "kande_nr")]
    kande_nr: String,

    #[serde(rename = "sisu")]
    sisu: Option<String>,

    #[serde(rename = "algus_kpv")]
    algus_kpv: Option<String>,

    #[serde(rename = "lopp_kpv")]
    lopp_kpv: String,

    #[serde(rename = "maj_aasta_algus")]
    maj_aasta_algus: Option<String>,

    #[serde(rename = "maj_aasta_lopp")]
    maj_aasta_lopp: Option<String>,

    #[serde(rename = "sisu_nr")]
    sisu_nr: Option<String>,

    #[serde(rename = "sisu_tekstina")]
    sisu_tekstina: Option<String>,

    #[serde(rename = "liik")]
    liik: Option<String>,

    #[serde(rename = "liik_tekstina")]
    liik_tekstina: Option<String>,
}

// #[derive(Serialize, Deserialize)]
// pub struct Kapitalid {
//     #[serde(rename = "item")]
//     item: KapitalidItem,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct KapitalidItem {
//     #[serde(rename = "kirje_id")]
//     kirje_id: String,
//
//     #[serde(rename = "kaardi_piirkond")]
//     kaardi_piirkond: String,
//
//     #[serde(rename = "kaardi_nr")]
//     kaardi_nr: String,
//
//     #[serde(rename = "kaardi_tyyp")]
//     kaardi_tyyp: String,
//
//     #[serde(rename = "kande_nr")]
//     kande_nr: String,
//
//     #[serde(rename = "kapitali_suurus")]
//     kapitali_suurus: String,
//
//     #[serde(rename = "kapitali_valuuta")]
//     kapitali_valuuta: String,
//
//     #[serde(rename = "kapitali_valuuta_tekstina")]
//     kapitali_valuuta_tekstina: String,
//
//     #[serde(rename = "algus_kpv")]
//     algus_kpv: String,
//
//     #[serde(rename = "lopp_kpv")]
//     lopp_kpv: String,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct MarkusedKaardil {
//     #[serde(rename = "item")]
//     item: MarkusedKaardilItem,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct MarkusedKaardilItem {
//     #[serde(rename = "kirje_id")]
//     kirje_id: String,
//
//     #[serde(rename = "kaardi_piirkond")]
//     kaardi_piirkond: String,
//
//     #[serde(rename = "kaardi_nr")]
//     kaardi_nr: String,
//
//     #[serde(rename = "kaardi_tyyp")]
//     kaardi_tyyp: String,
//
//     #[serde(rename = "kande_nr")]
//     kande_nr: String,
//
//     #[serde(rename = "veerg_nr")]
//     veerg_nr: String,
//
//     #[serde(rename = "tyyp")]
//     tyyp: String,
//
//     #[serde(rename = "tyyp_tekstina")]
//     tyyp_tekstina: String,
//
//     #[serde(rename = "sisu")]
//     sisu: String,
//
//     #[serde(rename = "algus_kpv")]
//     algus_kpv: String,
//
//     #[serde(rename = "lopp_kpv")]
//     lopp_kpv: String,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct Pohikirjad {
//     #[serde(rename = "item")]
//     item: PohikirjadItem,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct PohikirjadItem {
//     #[serde(rename = "kirje_id")]
//     kirje_id: String,
//
//     #[serde(rename = "kaardi_piirkond")]
//     kaardi_piirkond: String,
//
//     #[serde(rename = "kaardi_nr")]
//     kaardi_nr: String,
//
//     #[serde(rename = "kaardi_tyyp")]
//     kaardi_tyyp: String,
//
//     #[serde(rename = "kande_nr")]
//     kande_nr: String,
//
//     #[serde(rename = "kinnitamise_kpv")]
//     kinnitamise_kpv: String,
//
//     #[serde(rename = "muutmise_kpv")]
//     muutmise_kpv: String,
//
//     #[serde(rename = "selgitus")]
//     selgitus: String,
//
//     #[serde(rename = "algus_kpv")]
//     algus_kpv: String,
//
//     #[serde(rename = "lopp_kpv")]
//     lopp_kpv: String,
//
//     #[serde(rename = "sisaldab_erioigusi")]
//     sisaldab_erioigusi: String,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct Staatused {
//     #[serde(rename = "item")]
//     item: StaatusedItem,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct StaatusedItem {
//     #[serde(rename = "kaardi_piirkond")]
//     kaardi_piirkond: String,
//
//     #[serde(rename = "kaardi_nr")]
//     kaardi_nr: String,
//
//     #[serde(rename = "kaardi_tyyp")]
//     kaardi_tyyp: String,
//
//     #[serde(rename = "kande_nr")]
//     kande_nr: String,
//
//     #[serde(rename = "staatus")]
//     staatus: String,
//
//     #[serde(rename = "staatus_tekstina")]
//     staatus_tekstina: String,
//
//     #[serde(rename = "algus_kpv")]
//     algus_kpv: String,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct TeatatudTegevusalad {
//     #[serde(rename = "item")]
//     item: TeatatudTegevusaladItem,
// }
//
// #[derive(Serialize, Deserialize)]
// pub struct TeatatudTegevusaladItem {
//     #[serde(rename = "kirje_id")]
//     kirje_id: String,
//
//     #[serde(rename = "emtak_kood")]
//     emtak_kood: String,
//
//     #[serde(rename = "emtak_tekstina")]
//     emtak_tekstina: String,
//
//     #[serde(rename = "emtak_versioon")]
//     emtak_versioon: String,
//
//     #[serde(rename = "emtak_versioon_tekstina")]
//     emtak_versioon_tekstina: String,
//
//     #[serde(rename = "nace_kood")]
//     nace_kood: String,
//
//     #[serde(rename = "on_pohitegevusala")]
//     on_pohitegevusala: String,
//
//     #[serde(rename = "algus_kpv")]
//     algus_kpv: String,
//
//     #[serde(rename = "lopp_kpv")]
//     lopp_kpv: String,
// }
