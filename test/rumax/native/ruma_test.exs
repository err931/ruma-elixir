defmodule Rumax.Native.RumaTest do
  use ExUnit.Case, async: true

  alias Rumax.Native.Ruma

  @server_name "example.com"
  @key_version "1"
  @room_version "12"

  defp generate_keypair do
    jwk = JOSE.JWK.generate_key({:okp, :Ed25519})

    {_, der} = JOSE.JWK.to_der(jwk)

    {_, fields} = JOSE.JWK.to_public_map(jwk)

    public_key_b64 =
      fields
      |> Map.get("x")
      |> Base.url_decode64!(padding: false)
      |> Base.encode64(padding: false)

    {der, public_key_b64}
  end

  defp single_signature(signatures) do
    server_signatures = Map.fetch!(signatures, @server_name)
    assert [{key_version, signature}] = Map.to_list(server_signatures)
    assert key_version == "ed25519:" <> @key_version
    assert is_binary(signature)

    {key_version, signature}
  end

  defp event_json do
    Jason.encode!(%{
      "event_id" => "$abc:example.com",
      "origin" => "example.com",
      "origin_server_ts" => 1234,
      "room_id" => "!room:example.com",
      "sender" => "@alice:example.com",
      "type" => "m.room.message",
      "content" => %{"body" => "hello"}
    })
  end

  describe "JSON decode errors" do
    test "returns bad_json for malformed JSON" do
      assert {:error, {:bad_json, %{message: message}}} = Ruma.content_hash("{invalid}")
      assert is_binary(message)
      refute String.trim(message) == ""
    end
  end

  describe "content_hash" do
    test "returns an unpadded base64 content hash" do
      assert {:ok, hash} = Ruma.content_hash(event_json())

      assert is_binary(hash)
      refute hash == ""
      refute String.contains?(hash, "=")
      assert {:ok, _decoded} = Base.decode64(hash, padding: false)
    end
  end

  describe "canonical json" do
    test "canonicalizes JSON for signing without signatures and unsigned fields" do
      json = ~s({"b":2,"unsigned":{"x":1},"a":1,"signatures":{"foo":"bar"}})
      assert {:ok, canonical} = Ruma.to_canonical_json_string_for_signing(json)
      assert canonical == ~s({"a":1,"b":2})
    end
  end

  describe "sign_json_signatures" do
    test "signs JSON and returns the generated signatures" do
      {der, _public_key_b64} = generate_keypair()
      json = ~s({"a":1})

      assert {:ok, signatures_json} =
               Ruma.sign_json_signatures(@server_name, der, @key_version, json)

      signatures = Jason.decode!(signatures_json)
      {_returned_key_version, _signature} = single_signature(signatures)
      refute Map.has_key?(signatures, "a")
      refute Map.has_key?(signatures, "signatures")
    end

    test "verifies JSON signed with the matching public key" do
      {der, public_key_b64} = generate_keypair()
      json = ~s({"a":1})

      assert {:ok, signatures_json} =
               Ruma.sign_json_signatures(@server_name, der, @key_version, json)

      signatures = Jason.decode!(signatures_json)
      {returned_key_version, _signature} = single_signature(signatures)

      signed_json =
        json
        |> Jason.decode!()
        |> Map.put("signatures", signatures)
        |> Jason.encode!()

      assert {:ok, {}} =
               Ruma.verify_json(
                 %{@server_name => %{returned_key_version => public_key_b64}},
                 signed_json
               )
    end
  end

  describe "key decode errors" do
    test "returns invalid_signing_key for an invalid private key" do
      json = ~s({"type":"m.test","content":{"body":"hi"}})

      assert {:error, {:invalid_signing_key, %{message: message}}} =
               Ruma.sign_json_signatures(@server_name, <<1, 2, 3>>, @key_version, json)

      assert is_binary(message)
      refute String.trim(message) == ""
    end
  end

  describe "public key decode errors" do
    test "returns refused for an invalid public key" do
      json = ~s({"signatures":{"example.com":{"ed25519:1":"abc"}}})

      public_keys = %{@server_name => %{@key_version => "lorem-ipsum"}}

      assert {:error, {:refused, %{message: message}}} = Ruma.verify_json(public_keys, json)
      assert is_binary(message)
      refute String.trim(message) == ""
    end

    test "returns bad_json for an invalid signatures structure" do
      json = ~s({"signatures":[]})

      assert {:error, {:bad_json, %{message: message}}} =
               Ruma.verify_json(%{@server_name => %{}}, json)

      assert is_binary(message)
      refute String.trim(message) == ""
    end

    test "returns refused when event verification uses an invalid public key" do
      {der, _public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(
                 @server_name,
                 der,
                 @key_version,
                 @room_version,
                 event_json()
               )

      signed_event = Jason.decode!(signed_event_json)

      {returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))

      public_keys = %{@server_name => %{returned_key_version => "lorem-ipsum"}}

      assert {:error, {:refused, %{message: message}}} =
               Ruma.verify_event(public_keys, @room_version, signed_event_json)

      assert is_binary(message)
      refute String.trim(message) == ""
    end
  end

  describe "event hashing" do
    test "adds a SHA-256 content hash to an event" do
      assert {:ok, updated} = Ruma.add_content_hash_to_event(event_json())
      decoded = Jason.decode!(updated)
      assert get_in(decoded, ["hashes", "sha256"])
    end

    test "replaces the SHA-256 content hash while preserving other hashes" do
      json =
        event_json()
        |> Jason.decode!()
        |> put_in(["hashes"], %{"sha256" => "old_hash", "blake2b" => "keep_hash"})
        |> Jason.encode!()

      assert {:ok, updated} = Ruma.add_content_hash_to_event(json)
      decoded = Jason.decode!(updated)

      refute get_in(decoded, ["hashes", "sha256"]) == "old_hash"
      assert get_in(decoded, ["hashes", "blake2b"]) == "keep_hash"
    end
  end

  describe "event signing and verification" do
    test "signs an event without adding a content hash" do
      {der, _public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.sign_event(@server_name, der, @key_version, @room_version, event_json())

      signed_event = Jason.decode!(signed_event_json)

      {_returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))

      refute Map.has_key?(signed_event, "hashes")
    end

    test "adds a content hash and signature to an event" do
      {der, _public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(
                 @server_name,
                 der,
                 @key_version,
                 @room_version,
                 event_json()
               )

      signed_event = Jason.decode!(signed_event_json)

      assert is_binary(get_in(signed_event, ["hashes", "sha256"]))

      {_returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))
    end

    test "fully verifies a signed event with a valid content hash" do
      {der, public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(
                 @server_name,
                 der,
                 @key_version,
                 @room_version,
                 event_json()
               )

      signed_event = Jason.decode!(signed_event_json)

      {returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))

      assert {:ok, :all} =
               Ruma.verify_event(
                 %{@server_name => %{returned_key_version => public_key_b64}},
                 @room_version,
                 signed_event_json
               )
    end

    test "returns refused when signature verification fails" do
      {der, public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(
                 @server_name,
                 der,
                 @key_version,
                 @room_version,
                 event_json()
               )

      signed_event = Jason.decode!(signed_event_json)

      {returned_key_version, signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))

      tampered_event_json =
        signed_event
        |> put_in(
          ["signatures", @server_name, returned_key_version],
          String.reverse(signature)
        )
        |> Jason.encode!()

      assert {:error, {:refused, %{message: message}}} =
               Ruma.verify_event(
                 %{@server_name => %{returned_key_version => public_key_b64}},
                 @room_version,
                 tampered_event_json
               )

      assert is_binary(message)
      refute String.trim(message) == ""
    end
  end

  describe "required_server_signatures_to_verify_event" do
    test "returns the servers whose signatures are required" do
      assert {:ok, servers} =
               Ruma.required_server_signatures_to_verify_event(@room_version, event_json())

      assert is_list(servers)
      assert Enum.all?(servers, &is_binary/1)
    end
  end

  describe "verify_event signatures_only" do
    test "verifies only signatures when the content hash does not match" do
      {der, public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(
                 @server_name,
                 der,
                 @key_version,
                 @room_version,
                 event_json()
               )

      tampered_json =
        signed_event_json
        |> Jason.decode!()
        |> put_in(["content", "body"], "tampered")
        |> Jason.encode!()

      {returned_key_version, _signature} =
        single_signature(Map.fetch!(Jason.decode!(signed_event_json), "signatures"))

      assert {:ok, :signatures_only} =
               Ruma.verify_event(
                 %{@server_name => %{returned_key_version => public_key_b64}},
                 @room_version,
                 tampered_json
               )
    end
  end

  describe "reference_hash" do
    test "returns an unpadded base64 reference hash" do
      assert {:ok, hashed_json} = Ruma.add_content_hash_to_event(event_json())

      assert {:ok, hash} = Ruma.reference_hash(@room_version, hashed_json)

      assert is_binary(hash)
      refute String.contains?(hash, "=")
    end

    test "returns the same reference hash for the same event" do
      {:ok, hashed_json} = Ruma.add_content_hash_to_event(event_json())

      assert {:ok, hash1} = Ruma.reference_hash(@room_version, hashed_json)
      assert {:ok, hash2} = Ruma.reference_hash(@room_version, hashed_json)

      assert hash1 == hash2
    end

    test "returns a different reference hash when event content differs" do
      {:ok, hashed_json_a} = Ruma.add_content_hash_to_event(event_json())

      json_b =
        event_json()
        |> Jason.decode!()
        |> put_in(["content", "body"], "different")
        |> Jason.encode!()

      {:ok, hashed_json_b} = Ruma.add_content_hash_to_event(json_b)

      assert {:ok, hash_a} = Ruma.reference_hash(@room_version, hashed_json_a)
      assert {:ok, hash_b} = Ruma.reference_hash(@room_version, hashed_json_b)

      refute hash_a == hash_b
    end

    test "changes the reference hash when content hashing is skipped" do
      {:ok, hashed_json} = Ruma.add_content_hash_to_event(event_json())
      {:ok, hash_with_content_hash} = Ruma.reference_hash(@room_version, hashed_json)

      {:ok, hash_without_content_hash} = Ruma.reference_hash(@room_version, event_json())

      refute hash_with_content_hash == hash_without_content_hash
    end

    test "returns internal for an unsupported room version" do
      assert {:error, {:internal, %{message: message}}} =
               Ruma.reference_hash("invalid", event_json())

      assert is_binary(message)
      refute String.trim(message) == ""
    end
  end
end
