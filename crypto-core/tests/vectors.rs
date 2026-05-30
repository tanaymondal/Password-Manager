use base64::{engine::general_purpose::STANDARD, Engine as _};
use securevault_crypto_core::*;
use serde_json::Value;
use std::path::PathBuf;

fn load_vectors() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn dec(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

#[test]
fn decrypt_and_roundtrip_against_vectors() {
    let Some(root) = load_vectors() else {
        eprintln!("test-vectors/vectors.json not generated — skipping");
        return;
    };

    for v in root["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap_or("<unnamed>");
        let op = v["op"].as_str().unwrap();
        let inp = &v["input"];
        let exp = &v["expected"];

        match op {
            "wrap_vault_key" => {
                let kek = dec(inp["kek_raw_b64"].as_str().unwrap());
                let expected_vk = dec(inp["vault_key_raw_b64"].as_str().unwrap());
                let unwrapped = unwrap_vault_key(&kek, exp["wrapped_b64"].as_str().unwrap()).unwrap();
                assert_eq!(unwrapped, expected_vk, "{name} unwrap");
            }
            "encrypt_entry" => {
                let vk = dec(inp["vault_key_raw_b64"].as_str().unwrap());
                let c = EntryCiphertext {
                    encrypted_data: exp["encrypted_data"].as_str().unwrap().to_string(),
                    iv: exp["iv"].as_str().unwrap().to_string(),
                };
                assert_eq!(decrypt_entry(&vk, &c).unwrap(), inp["plaintext_json"].as_str().unwrap(), "{name}");
            }
            "encrypt_field" => {
                let vk = dec(inp["vault_key_raw_b64"].as_str().unwrap());
                let got = decrypt_field(&vk, exp["ciphertext"].as_str().unwrap()).unwrap();
                assert_eq!(got, inp["plaintext"].as_str().unwrap(), "{name}");
            }
            _ => {}
        }
    }
}

#[test]
fn roundtrips_without_vectors() {
    let vk = generate_vault_key().unwrap();

    let entry = r#"{"a":1,"b":"x"}"#;
    let c = encrypt_entry(&vk, entry).unwrap();
    assert!(c.encrypted_data.starts_with("v1:"));
    assert_eq!(decrypt_entry(&vk, &c).unwrap(), entry);

    let field = encrypt_field(&vk, "secret").unwrap();
    assert_eq!(decrypt_field(&vk, &field).unwrap(), "secret");
    assert_eq!(encrypt_field(&vk, "").unwrap(), "");
    assert_eq!(decrypt_field(&vk, "").unwrap(), "");

    let salt = generate_salt().unwrap();
    let mk = derive_master_key("pw", &STANDARD.decode(&salt).unwrap(), &DEFAULT_PARAMS).unwrap();
    let kek = derive_kek(&mk);
    let wrapped = wrap_vault_key(&kek, &vk).unwrap();
    assert_eq!(unwrap_vault_key(&kek, &wrapped).unwrap(), vk);

    let h1 = derive_auth_hash(&mk);
    let h2 = derive_auth_hash(&mk);
    assert_eq!(h1, h2);
    assert!(unwrap_vault_key(&kek, &STANDARD.encode([0u8; 60])).is_err());
}


