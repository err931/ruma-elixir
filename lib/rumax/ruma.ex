defmodule Rumax.Ruma do
  @moduledoc """
  Rustler bindings for the ruma-signatures crate.
  """

  alias Rumax.Native.Ruma

  defdelegate add_content_hash_to_event(json), to: Ruma

  defdelegate content_hash(json), to: Ruma

  defdelegate hash_and_sign_event(entity_id, key_pair, key_version, room_version, json),
    to: Ruma

  defdelegate reference_hash(room_version, json), to: Ruma

  defdelegate required_server_signatures_to_verify_event(room_version, json),
    to: Ruma

  defdelegate sign_event(entity_id, key_pair, key_version, room_version, json),
    to: Ruma

  defdelegate sign_json_signatures(entity_id, key_pair, key_version, json),
    to: Ruma

  defdelegate to_canonical_json_string_for_signing(json), to: Ruma

  defdelegate verify_event(public_keys, room_version, json), to: Ruma

  defdelegate verify_json(public_keys, json), to: Ruma
end
