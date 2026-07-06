defmodule Rumax.Ruma do
  @moduledoc """
  Rustler bindings for the ruma-signatures crate.
  """

  alias Rumax.Native.Ruma

  @type public_key_map :: %{
          optional(String.t()) => %{optional(String.t()) => String.t()}
        }

  @type reason :: :bad_json | :invalid_signing_key | :refused | :internal
  @type signature_error :: {reason(), %{message: String.t()}}

  @type verified :: :all | :signatures_only

  @spec add_content_hash_to_event(binary()) :: {:ok, String.t()} | {:error, signature_error()}
  defdelegate add_content_hash_to_event(json), to: Ruma

  @spec content_hash(binary()) :: {:ok, String.t()} | {:error, signature_error()}
  defdelegate content_hash(json), to: Ruma

  @spec hash_and_sign_event(String.t(), binary(), String.t(), String.t(), binary()) ::
          {:ok, String.t()} | {:error, signature_error()}
  defdelegate hash_and_sign_event(entity_id, key_pair, key_version, room_version, json),
    to: Ruma

  @spec reference_hash(String.t(), binary()) :: {:ok, String.t()} | {:error, signature_error()}
  defdelegate reference_hash(room_version, json), to: Ruma

  @spec required_server_signatures_to_verify_event(String.t(), binary()) ::
          {:ok, [String.t()]} | {:error, signature_error()}
  defdelegate required_server_signatures_to_verify_event(room_version, json),
    to: Ruma

  @spec sign_event(String.t(), binary(), String.t(), String.t(), binary()) ::
          {:ok, String.t()} | {:error, signature_error()}
  defdelegate sign_event(entity_id, key_pair, key_version, room_version, json),
    to: Ruma

  @spec sign_json_signatures(String.t(), binary(), String.t(), binary()) ::
          {:ok, String.t()} | {:error, signature_error()}
  defdelegate sign_json_signatures(entity_id, key_pair, key_version, json),
    to: Ruma

  @spec to_canonical_json_string_for_signing(binary()) ::
          {:ok, String.t()} | {:error, signature_error()}
  defdelegate to_canonical_json_string_for_signing(json), to: Ruma

  @spec verify_event(public_key_map(), String.t(), binary()) ::
          {:ok, verified()} | {:error, signature_error()}
  defdelegate verify_event(public_keys, room_version, json), to: Ruma

  @spec verify_json(public_key_map(), binary()) :: :ok | {:error, signature_error()}
  def verify_json(public_keys, json) do
    case Ruma.verify_json(public_keys, json) do
      {:ok, _} -> :ok
      {:error, _reason} = error -> error
    end
  end
end
