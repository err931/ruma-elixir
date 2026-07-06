defmodule Rumax.Native.Ruma do
  @moduledoc """
  Rustler bindings for the ruma-signatures crate.
  """

  use Rustler, otp_app: :rumax, crate: "ruma_nif"

  @doc """
  Compute and add the content hash to the given event.

  This adds or overwrites the sha256 key in the hashes object of the event.

  ## Parameters

  * `json` - A JSON string.

  ## Returns

  * `{:ok, canonical_json}` - A JSON string representing the updated event.
  * `{:error, reason}` - An error message describing the failure.
  """
  def add_content_hash_to_event(_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Computes the content hash of the given event.

  The content hash of an event covers the complete event including the unredacted contents. It is used during federation and is described in the Matrix server-server specification.

  ## Parameters

  * `json` - A JSON string.

  ## Returns

  * `{:ok, base64}` - A base64-encoded string.
  * `{:error, reason}` - An error message describing the failure.
  """
  def content_hash(_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Hashes and signs an event and adds the hash and signature to objects under the keys hashes and signatures, respectively.

  If hashes and/or signatures are already present, the new data will be appended to the existing data.

  ## Parameters

  * `entity_id` - The identifier of the entity creating the signature. Generally this means a homeserver, e.g. “example.com”.
  * `key_pair` - The DER-encoded Ed25519 private key as a binary.
  * `key_version` - The ID of the signing key.
  * `room_version` - The Matrix room version identifier.
  * `json` - A JSON string representing the event.

  ## Returns

  * `{:ok, canonical_json}` - A JSON string representing the updated event.
  * `{:error, reason}` - An error message describing the failure.
  """
  def hash_and_sign_event(_entity_id, _key_pair, _key_version, _room_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Computes the reference hash of the given event.

  The reference hash of an event covers the essential fields of an event, including content hashes.

  ## Parameters

  * `room_version` - The Matrix room version identifier.
  * `json` - A JSON string.

  ## Returns

  * `{:ok, base64}` - A base64-encoded string.
  * `{:error, reason}` - An error message describing the failure.
  """
  def reference_hash(_room_version, _json), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Get the list of servers whose signature must be checked to verify the given event.

  ## Parameters

  * `room_version` - The Matrix room version identifier.
  * `json` - A JSON string.

  ## Returns

  * `{:ok, server_names}` - A list of server names whose signatures must be verified.
  * `{:error, reason}` - An error message describing the failure.
  """
  def required_server_signatures_to_verify_event(_room_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Compute and add the signature of the given event.

  This adds or overwrites the signature for the given entity and key in the signatures object of the event.

  ## Parameters

  * `entity_id` - The identifier of the entity creating the signature. Generally this means a homeserver, e.g. “example.com”.
  * `key_pair` - The DER-encoded Ed25519 private key as a binary.
  * `key_version` - The ID of the signing key.
  * `room_version` - The Matrix room version identifier.
  * `json` - A JSON string representing the event.

  ## Returns

  * `{:ok, canonical_json}` - A JSON string representing the signed event.
  * `{:error, reason}` - An error message describing the failure.
  """
  def sign_event(_entity_id, _key_pair, _key_version, _room_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Signs an arbitrary JSON object and adds the signature to an object under the key signatures.

  If signatures is already present, the new signature will be appended to the existing ones.

  ## Parameters

  * `entity_id` - The identifier of the entity creating the signature. Generally this means a homeserver, e.g. “example.com”.
  * `key_pair` - The DER-encoded Ed25519 private key as a binary.
  * `key_version` - The ID of the signing key.
  * `json` - A JSON string representing the object to sign.

  ## Returns

  * `{:ok, canonical_json}` - A JSON string containing only the signatures field.
  * `{:error, reason}` - An error message describing the failure.
  """
  def sign_json_signatures(_entity_id, _key_pair, _key_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Serialize the given JSON object to prepare it for signing.

  This serializes the object to canonical JSON form without the signatures and unsigned fields.

  ## Parameters

  * `json` - A JSON string.

  ## Returns

  * `{:ok, canonical_json}` - The canonical JSON string.
  * `{:error, reason}` - An error message describing the failure.
  """
  def to_canonical_json_string_for_signing(_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Verifies that the signed event contains all the required valid signatures.

  ## Parameters

  * `public_keys` - A map from server names (domains) to their respective public keys.

  Example:

  ```elixir
  %{
    "example.org" => %{
      "ed25519:1" => "...", # old_verify_keys
      "ed25519:2" => "..." # verify_keys
    }
  }
  ```

  * `room_version` - The Matrix room version identifier.
  * `json` - A JSON string.

  ## Returns

  * `{:ok, :all}` - All signatures are valid and the content hashes match.
  * `{:ok, :signatures_only}` - All signatures are valid but the content hashes don't match. This may indicate a redacted event.
  * `{:error, reason}` - An error message describing the failure.
  """
  def verify_event(_public_keys, _room_version, _json), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Uses a set of public keys to verify a signed JSON object.

  ## Parameters

  * `public_keys` - A map from server names (domains) to their respective public keys.

  Example:

  ```elixir
  %{
    "example.org" => %{
      "ed25519:1" => "...", # old_verify_keys
      "ed25519:2" => "..." # verify_keys
    }
  }
  ```

  * `json` - A JSON string.

  ## Returns

  * `{:ok, {}}` - All signatures are valid.
  * `{:error, reason}` - An error message describing the failure.
  """
  def verify_json(_public_keys, _json), do: :erlang.nif_error(:nif_not_loaded)
end
