#![allow(unused)]

use firebase_jwt_claims_rs::{decoding_key, verify_firebase_token};
use jsonwebtoken::{decode, decode_header, Algorithm, Header, Validation};
use serde::{Deserialize, Serialize};

// Create a Claims structure with Serde derivatives and Debug.
// Use Option<> around the types of fields that might not appear in the token.
// If Option<> is not used, then validation will fail if the field is not present.
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

#[tokio::main]
async fn main() {
    // The token generated by Google Firebase
    let token = concat!(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBhYmQzYTQzMTc4YzE0MjlkNWE0NDBiYWUzNzM1NDRjMDlmNGUzODciLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiSm9obiBNdXJyYXkiLCJvcmdhbml6YXRpb25BZG1pbiI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9zZWN1cmV0b2tlbi5nb29nbGUuY29tL3N0dXRvci01NDdkNCIsImF1ZCI6InN0dXRvci01NDdkNCIsImF1dGhfdGltZSI6MTczNzY4NDY0MiwidXNlcl9pZCI6InpnQTBVeTY1YUJjcDNZREcwSG9ZUXQ4bk9tVzIiLCJzdWIiOiJ6Z0EwVXk2NWFCY3AzWURHMEhvWVF0OG5PbVcyIiwiaWF0IjoxNzM3Njg0NjQyLCJleHAiOjE3Mzc2ODgyNDIsImVtYWlsIjoiam9obkBnYXJkZW53YXkub3JnIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwaG9uZV9udW1iZXIiOiIrMTgwMTYyODA1NDMiLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7ImVtYWlsIjpbImpvaG5AZ2FyZGVud2F5Lm9yZyJdLCJwaG9uZSI6WyIrMTgwMTYyODA1NDMiXX0sInNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.TQUtxnla1aJ6izWrWjN0PuL9DEi0fD7pPy6UUN0QyVgDMoFF9wKWiRM8BY4JfqWObRCdjjIxmOW_eQszOJvBRv4RUWq79jHAiu6kgGiQeCzw5UNS-7ac-Bo24klIkYtzVKmROYghNbvNMQcpFOyBz8S23ZXpbBmgCzVDeiUk8Ogr3Vjn-zF5a28azRFon5GmCSjb2vMYEYjRlXhPZNwVAGP7LRxo6kteqyanEH7u7JHRYsJU6IjARfvhHNpiRaquGh99SsyIO_7SWKPKIKzVRm0WKJh8qQc8e6uyhZWbQ1IJ6IlZn637eQJnZkneafmB5wqjyJnpO_pcVQr5w3BQAg",
    ).to_string();

    // Decode the token header to check the algorithm
    let header: Header = match decode_header(&token) {
        Ok(header) => header,
        Err(e) => {
            println!("Error decoding token header: {}", e);
            return;
        }
    };

    println!("Token header: {:?}", header);

    // all validation.* are set to true by default.  In addition, specific fields can be checked for expected values.

    // Set the algorithm currently used by Firebase on 2025_01_23
    let mut validation = Validation::new(Algorithm::RS256);

    // Disable expiration validation for testing.
    // Most tests need to run after a copied token has expired, so we will turn this off for testing.
    // Don't turn it off for production verificaton of a token!
    validation.validate_exp = false;

    // In firebase tokents, the aud is the firebase project name
    validation.validate_aud = false; // Disable checks on the name of the audience.

    // For production, you probablly want to specify the audience and set validate_aud to true
    // validation.validate_aud = true;
    // validation.set_audience(&["stutor-dev"]);

    // Verify the token
    match verify_firebase_token::<Claims>(&token, &validation).await {
        Ok(_) => println!("Token is valid"),
        Err(e) => {
            println!("Token is invalid: {:?}", e);
            return;
        }
    }

    // Decode the token with the RSA public key
    let token_data = decode::<Claims>(&token, &decoding_key(), &validation).unwrap();

    // Print the claims to inspect the audience and other fields
    println!("Decoded claims: {:?}", token_data.claims);
}
