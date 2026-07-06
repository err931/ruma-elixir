use std::collections::HashMap;

use ruma_common::{
    canonical_json::CanonicalJsonObject, room_version_rules::RoomVersionRules, serde::Base64, RoomVersionId
};
use ruma_signatures::{Ed25519KeyPair, PublicKeyMap, PublicKeySet, VerificationError, Verified};
use rustler::{Binary, NifTaggedEnum, NifUnitEnum};

#[derive(NifUnitEnum)]
pub enum RumaVerified {
    All,
    SignaturesOnly,
}

#[derive(NifTaggedEnum)]
pub enum SignatureError {
    BadJson { message: String },
    InvalidSigningKey { message: String },
    Refused { message: String },
    Internal { message: String },
}

impl From<Verified> for RumaVerified {
    fn from(verified: Verified) -> Self {
        match verified {
            Verified::All => Self::All,
            Verified::Signatures => Self::SignaturesOnly,
        }
    }
}

impl From<VerificationError> for SignatureError {
    fn from(error: VerificationError) -> Self {
        let message = error.to_string();

        match error {
            VerificationError::Json(_) | VerificationError::ParseIdentifier { .. } => {
                Self::BadJson { message }
            }

            VerificationError::InvalidBase64Signature { .. }
            | VerificationError::UnsupportedAlgorithm
            | VerificationError::NoSignaturesForEntity(_)
            | VerificationError::NoPublicKeysForEntity(_)
            | VerificationError::NoSupportedSignatureForEntity(_)
            | VerificationError::Ed25519(_) => Self::Refused { message },

            _ => Self::Internal { message },
        }
    }
}

fn parse_json(json: &[u8]) -> Result<CanonicalJsonObject, SignatureError> {
    serde_json::from_slice(json).map_err(|e| SignatureError::BadJson {
        message: e.to_string(),
    })
}

fn to_json_string<T: serde::Serialize>(object: &T) -> Result<String, SignatureError> {
    serde_json::to_string(object).map_err(|e| SignatureError::Internal {
        message: e.to_string(),
    })
}

fn parse_key_pair(der: &[u8], key_version: String) -> Result<Ed25519KeyPair, SignatureError> {
    Ed25519KeyPair::from_der(der, key_version).map_err(|e| SignatureError::InvalidSigningKey {
        message: e.to_string(),
    })
}

fn parse_room_version(room_version: String) -> Result<RoomVersionRules, SignatureError> {
    let room_version_id =
        RoomVersionId::try_from(room_version).map_err(|e| SignatureError::Internal {
            message: e.to_string(),
        })?;

    room_version_id
        .rules()
        .ok_or_else(|| SignatureError::Internal {
            message: "Unsupported room version".to_string(),
        })
}

fn parse_public_keys(
    public_keys: HashMap<String, HashMap<String, String>>,
) -> Result<PublicKeyMap, SignatureError> {
    let mut public_key_map = PublicKeyMap::new();

    for (domain, keys) in public_keys {
        let mut key_set = PublicKeySet::new();

        for (key_id, pk_b64) in keys {
            let public_key = Base64::parse(&pk_b64).map_err(|e| SignatureError::Refused {
                message: e.to_string(),
            })?;

            key_set.insert(key_id, public_key);
        }

        public_key_map.insert(domain, key_set);
    }

    Ok(public_key_map)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn add_content_hash_to_event<'a>(json: Binary<'a>) -> Result<String, SignatureError> {
    let mut object = parse_json(json.as_slice())?;

    ruma_signatures::add_content_hash_to_event(&mut object).map_err(|e| {
        SignatureError::BadJson {
            message: e.to_string(),
        }
    })?;

    to_json_string(&object)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn content_hash<'a>(json: Binary<'a>) -> Result<String, SignatureError> {
    let object = parse_json(json.as_slice())?;

    ruma_signatures::content_hash(&object)
        .map(|hash| hash.encode())
        .map_err(|e| SignatureError::BadJson {
            message: e.to_string(),
        })
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash_and_sign_event<'a>(
    entity_id: String,
    key_pair: Binary<'a>,
    key_version: String,
    room_version: String,
    json: Binary<'a>,
) -> Result<String, SignatureError> {
    let mut object = parse_json(json.as_slice())?;

    let key_pair = parse_key_pair(key_pair.as_slice(), key_version)?;

    let rules = parse_room_version(room_version)?;

    ruma_signatures::hash_and_sign_event(&entity_id, &key_pair, &mut object, &rules.redaction)
        .map_err(|e| SignatureError::BadJson {
            message: e.to_string(),
        })?;

    to_json_string(&object)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn reference_hash<'a>(room_version: String, json: Binary<'a>) -> Result<String, SignatureError> {
    let object = parse_json(json.as_slice())?;

    let rules = parse_room_version(room_version)?;

    ruma_signatures::reference_hash(&object, &rules).map_err(|e| SignatureError::BadJson {
        message: e.to_string(),
    })
}

#[rustler::nif(schedule = "DirtyCpu")]
fn required_server_signatures_to_verify_event<'a>(
    room_version: String,
    json: Binary<'a>,
) -> Result<Vec<String>, SignatureError> {
    let object = parse_json(json.as_slice())?;

    let rules = parse_room_version(room_version)?;

    let servers =
        ruma_signatures::required_server_signatures_to_verify_event(&object, &rules.signatures)?;

    Ok(servers.into_iter().map(String::from).collect())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn sign_event<'a>(
    entity_id: String,
    key_pair: Binary<'a>,
    key_version: String,
    room_version: String,
    json: Binary<'a>,
) -> Result<String, SignatureError> {
    let mut object = parse_json(json.as_slice())?;

    let key_pair = parse_key_pair(key_pair.as_slice(), key_version)?;

    let rules = parse_room_version(room_version)?;

    ruma_signatures::sign_event(&entity_id, &key_pair, &mut object, &rules.redaction).map_err(
        |e| SignatureError::BadJson {
            message: e.to_string(),
        },
    )?;

    to_json_string(&object)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn sign_json_signatures<'a>(
    entity_id: String,
    key_pair: Binary<'a>,
    key_version: String,
    json: Binary<'a>,
) -> Result<String, SignatureError> {
    let mut object = parse_json(json.as_slice())?;

    let key_pair = parse_key_pair(key_pair.as_slice(), key_version)?;

    ruma_signatures::sign_json(&entity_id, &key_pair, &mut object).map_err(|e| {
        SignatureError::BadJson {
            message: e.to_string(),
        }
    })?;

    // Returns only the `signatures` field, not the full signed object.
    // Use `sign_event` instead if the complete signed event is needed.
    let signatures = object
        .remove("signatures")
        .ok_or_else(|| SignatureError::Internal {
            message: "Signature not found".to_string(),
        })?;

    to_json_string(&signatures)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn to_canonical_json_string_for_signing<'a>(json: Binary<'a>) -> Result<String, SignatureError> {
    let object = parse_json(json.as_slice())?;

    ruma_signatures::to_canonical_json_string_for_signing(&object).map_err(|e| {
        SignatureError::Internal {
            message: e.to_string(),
        }
    })
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_event<'a>(
    public_keys: HashMap<String, HashMap<String, String>>,
    room_version: String,
    json: Binary<'a>,
) -> Result<RumaVerified, SignatureError> {
    let object = parse_json(json.as_slice())?;

    let public_key_map = parse_public_keys(public_keys)?;

    let rules = parse_room_version(room_version)?;

    let verified = ruma_signatures::verify_event(&public_key_map, &object, &rules)?;

    Ok(verified.into())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_json<'a>(
    public_keys: HashMap<String, HashMap<String, String>>,
    json: Binary<'a>,
) -> Result<(), SignatureError> {
    let object = parse_json(json.as_slice())?;

    let public_key_map = parse_public_keys(public_keys)?;

    Ok(ruma_signatures::verify_json(&public_key_map, &object)?)
}
