use std::collections::HashMap;

use ruma_common::{canonical_json::CanonicalJsonObject, serde::Base64, RoomVersionId};
use ruma_signatures::{PublicKeyMap, PublicKeySet, Verified};
use rustler::{Atom, Binary};

mod atoms {
    rustler::atoms! {
        all,
        signatures_only,
    }
}

fn parse_json(json: &[u8]) -> Result<CanonicalJsonObject, String> {
    serde_json::from_slice(json).map_err(|e| e.to_string())
}

fn to_json_string<T: serde::Serialize>(object: &T) -> Result<String, String> {
    serde_json::to_string(object).map_err(|e| e.to_string())
}

fn parse_public_keys(
    public_keys: HashMap<String, HashMap<String, String>>,
) -> Result<PublicKeyMap, String> {
    let mut public_key_map = PublicKeyMap::new();

    for (domain, keys) in public_keys {
        let mut key_set = PublicKeySet::new();

        for (key_id, pk_b64) in keys {
            let public_key = Base64::parse(&pk_b64).map_err(|e| e.to_string())?;
            key_set.insert(key_id, public_key);
        }

        public_key_map.insert(domain, key_set);
    }

    Ok(public_key_map)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn add_content_hash_to_event<'a>(json: Binary<'a>) -> Result<String, String> {
    let mut object = parse_json(json.as_slice())?;

    ruma_signatures::add_content_hash_to_event(&mut object).map_err(|e| e.to_string())?;

    to_json_string(&object)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn content_hash<'a>(json: Binary<'a>) -> Result<String, String> {
    let object = parse_json(json.as_slice())?;

    let hash = ruma_signatures::content_hash(&object).map_err(|e| e.to_string())?;

    Ok(hash.encode())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash_and_sign_event<'a>(
    entity_id: String,
    key_pair: Binary<'a>,
    key_version: String,
    room_version: String,
    json: Binary<'a>,
) -> Result<String, String> {
    let mut object = parse_json(json.as_slice())?;

    let key_pair = ruma_signatures::Ed25519KeyPair::from_der(key_pair.as_slice(), key_version)
        .map_err(|e| e.to_string())?;

    let room_version_id = RoomVersionId::try_from(room_version).map_err(|e| e.to_string())?;
    let rules = room_version_id
        .rules()
        .ok_or_else(|| "unknown_room_version".to_string())?;

    ruma_signatures::hash_and_sign_event(&entity_id, &key_pair, &mut object, &rules.redaction)
        .map_err(|e| e.to_string())?;

    to_json_string(&object)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn reference_hash<'a>(room_version: String, json: Binary<'a>) -> Result<String, String> {
    let object = parse_json(json.as_slice())?;

    let room_version_id = RoomVersionId::try_from(room_version).map_err(|e| e.to_string())?;
    let rules = room_version_id
        .rules()
        .ok_or_else(|| "unknown_room_version".to_string())?;

    let hash = ruma_signatures::reference_hash(&object, &rules).map_err(|e| e.to_string())?;

    Ok(hash)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn required_server_signatures_to_verify_event<'a>(
    room_version: String,
    json: Binary<'a>,
) -> Result<Vec<String>, String> {
    let object = parse_json(json.as_slice())?;

    let room_version_id = RoomVersionId::try_from(room_version).map_err(|e| e.to_string())?;
    let rules = room_version_id
        .rules()
        .ok_or_else(|| "unknown_room_version".to_string())?;

    let result =
        ruma_signatures::required_server_signatures_to_verify_event(&object, &rules.signatures)
            .map_err(|e| e.to_string())?;

    let server_list = result.into_iter().map(String::from).collect();

    Ok(server_list)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn sign_event<'a>(
    entity_id: String,
    key_pair: Binary<'a>,
    key_version: String,
    room_version: String,
    json: Binary<'a>,
) -> Result<String, String> {
    let mut object = parse_json(json.as_slice())?;

    let key_pair = ruma_signatures::Ed25519KeyPair::from_der(key_pair.as_slice(), key_version)
        .map_err(|e| e.to_string())?;

    let room_version_id = RoomVersionId::try_from(room_version).map_err(|e| e.to_string())?;
    let rules = room_version_id
        .rules()
        .ok_or_else(|| "unknown_room_version".to_string())?;

    ruma_signatures::sign_event(&entity_id, &key_pair, &mut object, &rules.redaction)
        .map_err(|e| e.to_string())?;

    to_json_string(&object)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn sign_json_signatures<'a>(
    entity_id: String,
    key_pair: Binary<'a>,
    key_version: String,
    json: Binary<'a>,
) -> Result<String, String> {
    let mut object = parse_json(json.as_slice())?;

    let key_pair = ruma_signatures::Ed25519KeyPair::from_der(key_pair.as_slice(), key_version)
        .map_err(|e| e.to_string())?;

    ruma_signatures::sign_json(&entity_id, &key_pair, &mut object).map_err(|e| e.to_string())?;

    // Returns only the `signatures` field, not the full signed object.
    // Use `sign_event` instead if the complete signed event is needed.
    let signatures = object.remove("signatures").ok_or("missing_signatures")?;

    to_json_string(&signatures)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn to_canonical_json_string_for_signing<'a>(json: Binary<'a>) -> Result<String, String> {
    let object = parse_json(json.as_slice())?;

    let canonical = ruma_signatures::to_canonical_json_string_for_signing(&object)
        .map_err(|e| e.to_string())?;

    Ok(canonical)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_event<'a>(
    public_keys: HashMap<String, HashMap<String, String>>,
    room_version: String,
    json: Binary<'a>,
) -> Result<Atom, String> {
    let object = parse_json(json.as_slice())?;

    let public_key_map = parse_public_keys(public_keys)?;

    let room_version_id = RoomVersionId::try_from(room_version).map_err(|e| e.to_string())?;
    let rules = room_version_id
        .rules()
        .ok_or_else(|| "unknown_room_version".to_string())?;

    match ruma_signatures::verify_event(&public_key_map, &object, &rules) {
        Ok(Verified::All) => Ok(atoms::all()),
        Ok(Verified::Signatures) => Ok(atoms::signatures_only()),
        Err(e) => Err(e.to_string()),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_json<'a>(
    public_keys: HashMap<String, HashMap<String, String>>,
    json: Binary<'a>,
) -> Result<(), String> {
    let object = parse_json(json.as_slice())?;

    let public_key_map = parse_public_keys(public_keys)?;

    ruma_signatures::verify_json(&public_key_map, &object).map_err(|e| e.to_string())
}
