defmodule Rumax.Native.Ruma do
  @moduledoc false

  use Rustler, otp_app: :rumax, crate: "ruma_nif"

  def add_content_hash_to_event(_json), do: :erlang.nif_error(:nif_not_loaded)

  def content_hash(_json), do: :erlang.nif_error(:nif_not_loaded)

  def hash_and_sign_event(_entity_id, _key_pair, _key_version, _room_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  def reference_hash(_room_version, _json), do: :erlang.nif_error(:nif_not_loaded)

  def required_server_signatures_to_verify_event(_room_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  def sign_event(_entity_id, _key_pair, _key_version, _room_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  def sign_json_signatures(_entity_id, _key_pair, _key_version, _json),
    do: :erlang.nif_error(:nif_not_loaded)

  def to_canonical_json_string_for_signing(_json), do: :erlang.nif_error(:nif_not_loaded)

  def verify_event(_public_keys, _room_version, _json), do: :erlang.nif_error(:nif_not_loaded)

  def verify_json(_public_keys, _json), do: :erlang.nif_error(:nif_not_loaded)
end
