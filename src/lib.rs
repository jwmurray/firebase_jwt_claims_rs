#![allow(unused)]

use jsonwebtoken::decode;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode_header, errors::Error, Algorithm, DecodingKey, Header, Validation};

const GOOLGE_FIREBASE_PUBLIC_KEY_PEM: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcjP55NqPhSHA0e0P0kq
kkeXAJcIUUMJTGfP6aPgK4Zj+yRqyF+s39kePjTYgefUS2REpmX77MbNWho3aN7g
N+9BFxY9E+xkuGG2MYO27Cj0/y1UQZLjfbXAxZulJVGHyJ69WnwtDthCulzaGAl8
N22/ADDMyCdoM08nZIT+zGgQ6HoiJLThW+d/M+4l4sO6d/LzYbWNEhz1LCaPfJvP
909vfmbcUH6JUAIWE7cm2Imy9EPQt5z142svE7hoLyBtudj8Zv4NzcMsbY6oD1tC
CyBN8oj6MJ2CO9N/gbI31ZbOADKko+hFo2LRMy0LjwwezGU/68KAoo3TzeVSFu7k
GwIDAQAB
-----END PUBLIC KEY-----"#;

pub async fn verify_firebase_token<T>(
    firebase_token: &str,
    validation: &Validation,
) -> Result<bool, Error>
where
    T: serde::de::DeserializeOwned,
{
    // Let's just include google's firebase public key which is valid as of 2025_01_23.
    // If it changes, that means that Google has had a major security breacn, and the world is coming to an end anyways.

    // See the commented code at the end which gives an automated way to get the new firebase google key.
    // Todo:  add this as a function in the library and a periodic function be called at startup of a using app.

    // Ensure the public key from the file is used
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(GOOLGE_FIREBASE_PUBLIC_KEY_PEM.as_bytes()).unwrap();

    // Decode the token
    let token_data = match decode::<T>(firebase_token, &decoding_key, &validation) {
        Ok(token_data) => token_data,
        Err(e) => return Err(e),
    };

    Ok(true)
}

pub async fn firebase_get_token_header_no_validation(
    firebase_token: &str,
) -> Result<Header, Error> {
    // Decode the token header to check the algorithm
    match decode_header(&firebase_token) {
        Ok(header) => Ok(header),
        Err(e) => Err(e),
    }
}

pub fn decoding_key() -> DecodingKey {
    jsonwebtoken::DecodingKey::from_rsa_pem(GOOLGE_FIREBASE_PUBLIC_KEY_PEM.as_bytes()).unwrap()
}

// Get the firebase public key from google.  We hard-coded the public key above.  If that changes, the following function can be used to get
// the updated firebase public key from google.  This function is not used in the current implementation, but is left here for future reference.
pub async fn get_firebase_public_key(
    header: Header,
) -> Result<String, jsonwebtoken::errors::ErrorKind> {
    // add reqwest to Cargo.toml
    use reqwest::get;
    use serde_json;
    let response = reqwest::get(
        "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
    )
    .await
    .unwrap()
    .text()
    .await
    .unwrap();

    let public_keys: std::collections::HashMap<String, String> =
        serde_json::from_str(&response).unwrap();

    // Get the key ID (kid) from the header
    let kid = header.kid.unwrap();

    // Get the corresponding public key
    let result = match public_keys.get(&kid) {
        Some(public_key) => Ok(public_key.to_string()),
        None => Err(ErrorKind::InvalidSignature),
    };
    return result;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctor::ctor;
    use jsonwebtoken::{decode_header, errors::Error, errors::ErrorKind, Header, Validation};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        // required fields
        aud: String,
        sub: String,
        exp: u64,
        iss: String,
        auth_time: u64,
        iat: u64,

        // optional customized fields
        user_id: Option<String>,
        name: Option<String>,
        email: Option<String>,
        email_verified: Option<bool>,
        phone_number: Option<String>,
        sign_in_provider: Option<String>, // e.g. "password"
        admin: Option<bool>,
        student: Option<bool>,
        tutor: Option<bool>,
        super_admin: Option<bool>,
        school_admin: Option<bool>,
        organization_admin: Option<bool>,
        user_group_admin: Option<bool>,
        staff: Option<bool>,
    }

    fn setup() -> String {
        let expired_test_token =
            include_str!("../tests/expired_firebase_non_production_token.txt").to_string();
        let mut validation: Validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        let key = decoding_key();
        let decoding_key = decoding_key();

        let header: Header = decode_header(&expired_test_token).unwrap();
        expired_test_token
    }

    #[tokio::test]
    async fn test_verifty_firebase_token_empty_token() {
        // Empty token should result in an InvalidToken error.
        let mut validation: Validation = Validation::new(jsonwebtoken::Algorithm::RS256);

        let result = verify_firebase_token::<Claims>("", &validation).await;
        match result {
            Ok(_) => panic!("Expected error"),
            Err(e) => {
                assert_eq!(e.kind(), &ErrorKind::InvalidToken);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_token_midding_signature() {
        // Empty token should result in an InvalidToken error.
        let mut validation: Validation = Validation::new(jsonwebtoken::Algorithm::RS256);

        // Split the token into header and payload, omitting the signature
        let token = concat!(
        /* header*/ "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBhYmQzYTQzMTc4YzE0MjlkNWE0NDBiYWUzNzM1NDRjMDlmNGUzODciLCJ0eXAiOiJKV1QifQ",
        /* payload with no signature */ ".eyJuYW1lIjoiczFAZ2FyZGVud2F5Lm9yZyBtdXJyYXkiLCJzdHVkZW50Ijp0cnVlLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vc3R1dG9yLWRldiIsImF1ZCI6InN0dXRvci1kZXYiLCJhdXRoX3RpbWUiOjE3Mzc2OTU1NTUsInVzZXJfaWQiOiI2VENqMGlQZVFLZmM4RGpMTVN5SHpRNVRWN1YyIiwic3ViIjoiNlRDajBpUGVRS2ZjOERqTE1TeUh6UTVUVjdWMiIsImlhdCI6MTczNzY5NTU1NSwiZXhwIjoxNzM3Njk5MTU1LCJlbWFpbCI6InMxQGdhcmRlbndheS5vcmciLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicGhvbmVfbnVtYmVyIjoiKzE4MDE2MjgwNTQzIiwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJzMUBnYXJkZW53YXkub3JnIl0sInBob25lIjpbIisxODAxNjI4MDU0MyJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19",
        /* empty signature */ "."
    ).to_string();

        let result = verify_firebase_token::<Claims>("", &validation).await;
        match result {
            Ok(_) => panic!("Expected error"),
            Err(e) => {
                assert_eq!(e.kind(), &ErrorKind::InvalidToken);
            }
        }
    }

    #[tokio::test]
    async fn test_token_verification_with_wrong_alogrithm_fails() {
        let expired_test_token = setup();
        // Wrong algorithm, the right one is RS256
        let mut validation: Validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = false; // This says, expired tokens are OK.  Do not set this in production.  This is used for the test token only!!  Can be improved by creating a valid current token as part of the test setup.
        validation.validate_aud = false;
        validation.algorithms = vec![jsonwebtoken::Algorithm::ES256];

        let result = verify_firebase_token::<Claims>(&expired_test_token, &validation).await;
        match result {
            Ok(_) => panic!("Expected error"),
            Err(e) => {
                assert_eq!(e.kind(), &ErrorKind::InvalidAlgorithm);
            }
        }
    }

    #[tokio::test]
    async fn test_token_verification_with_correct_alogrithm_success() {
        let expired_test_token = setup();
        // Wrong algorithm, the right one is RS256
        let mut validation: Validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false; // This says, expired tokens are OK.  Do not set this in production.  This is used for the test token only!!  Can be improved by creating a valid current token as part of the test setup.
        validation.validate_aud = false;

        let result = verify_firebase_token::<Claims>(&expired_test_token, &validation).await;
        assert_eq!(result.unwrap(), true);
    }
}
