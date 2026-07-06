defmodule Rumax.Native.RumaTest do
  use ExUnit.Case, async: true

  alias Rumax.Native.Ruma

  @server_name "example.com"
  @key_version "1"

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
    test "returns {:error, reason} when JSON is invalid" do
      assert {:error, reason} = Ruma.content_hash("{invalid}")
      assert is_binary(reason)
      refute String.trim(reason) == ""
    end
  end

  describe "content_hash" do
    test "returns an unpadded base64 string" do
      assert {:ok, hash} = Ruma.content_hash(event_json())

      assert is_binary(hash)
      refute hash == ""
      refute String.contains?(hash, "=")
      assert {:ok, _decoded} = Base.decode64(hash, padding: false)
    end
  end

  describe "canonical json" do
    test "excludes signatures and unsigned and is stable" do
      json = ~s({"b":2,"unsigned":{"x":1},"a":1,"signatures":{"foo":"bar"}})
      assert {:ok, canonical} = Ruma.to_canonical_json_string_for_signing(json)
      assert canonical == ~s({"a":1,"b":2})
    end
  end

  describe "sign_json" do
    test "returns only the signatures field" do
      {der, _public_key_b64} = generate_keypair()
      json = ~s({"a":1})

      assert {:ok, signatures_json} = Ruma.sign_json(@server_name, der, @key_version, json)

      signatures = Jason.decode!(signatures_json)
      {_returned_key_version, _signature} = single_signature(signatures)
      refute Map.has_key?(signatures, "a")
      refute Map.has_key?(signatures, "signatures")
    end

    test "signed JSON can be verified by verify_json" do
      {der, public_key_b64} = generate_keypair()
      json = ~s({"a":1})

      assert {:ok, signatures_json} = Ruma.sign_json(@server_name, der, @key_version, json)
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
    test "returns {:error, reason} when DER private key is invalid" do
      json = ~s({"type":"m.test","content":{"body":"hi"}})
      assert {:error, reason} = Ruma.sign_json(@server_name, <<1, 2, 3>>, @key_version, json)
      assert is_binary(reason)
      refute String.trim(reason) == ""
    end

    test "event signing functions return {:error, reason} when DER private key is invalid" do
      assert {:error, reason_1} =
               Ruma.sign_event(@server_name, <<1, 2, 3>>, @key_version, event_json())

      assert {:error, reason_2} =
               Ruma.hash_and_sign_event(@server_name, <<1, 2, 3>>, @key_version, event_json())

      assert is_binary(reason_1)
      assert is_binary(reason_2)
      refute String.trim(reason_1) == ""
      refute String.trim(reason_2) == ""
    end
  end

  describe "public key decode errors" do
    test "returns {:error, reason} when public key base64 is invalid" do
      json = ~s({"signatures":{"example.com":{"ed25519:1":"abc"}}})

      public_keys = %{@server_name => %{@key_version => "lorem-ipsum"}}

      assert {:error, reason} = Ruma.verify_json(public_keys, json)
      assert is_binary(reason)
      refute String.trim(reason) == ""
    end

    test "verify_event returns {:error, reason} when public key base64 is invalid" do
      {der, _public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(@server_name, der, @key_version, event_json())

      signed_event = Jason.decode!(signed_event_json)

      {returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))

      public_keys = %{@server_name => %{returned_key_version => "lorem-ipsum"}}

      assert {:error, reason} = Ruma.verify_event(public_keys, signed_event_json)
      assert is_binary(reason)
      refute String.trim(reason) == ""
    end
  end

  describe "event hashing" do
    test "adds hashes.sha256" do
      assert {:ok, updated} = Ruma.add_content_hash_to_event(event_json())
      decoded = Jason.decode!(updated)
      assert get_in(decoded, ["hashes", "sha256"])
    end

    test "overwrites hashes.sha256 and preserves other hashes" do
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
    test "sign_event adds signatures without adding hashes" do
      {der, _public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.sign_event(@server_name, der, @key_version, event_json())

      signed_event = Jason.decode!(signed_event_json)

      {_returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))

      refute Map.has_key?(signed_event, "hashes")
    end

    test "hash_and_sign_event adds hashes and signatures" do
      {der, _public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(@server_name, der, @key_version, event_json())

      signed_event = Jason.decode!(signed_event_json)

      assert is_binary(get_in(signed_event, ["hashes", "sha256"]))

      {_returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))
    end

    test "verify_event returns {:ok, :all} for a signed event with a valid content hash" do
      {der, public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(@server_name, der, @key_version, event_json())

      signed_event = Jason.decode!(signed_event_json)

      {returned_key_version, _signature} =
        single_signature(Map.fetch!(signed_event, "signatures"))

      assert {:ok, :all} =
               Ruma.verify_event(
                 %{@server_name => %{returned_key_version => public_key_b64}},
                 signed_event_json
               )
    end
  end

  describe "required_server_signatures_to_verify_event" do
    test "returns a list of strings" do
      assert {:ok, servers} = Ruma.required_server_signatures_to_verify_event(event_json())

      assert is_list(servers)
      assert Enum.all?(servers, &is_binary/1)
    end
  end

  describe "verify_event signatures_only" do
    test "returns {:ok, :signatures_only} when content hash does not match" do
      {der, public_key_b64} = generate_keypair()

      assert {:ok, signed_event_json} =
               Ruma.hash_and_sign_event(@server_name, der, @key_version, event_json())

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
                 tampered_json
               )
    end
  end

  describe "reference_hash" do
    test "returns a base64 string without padding" do
      assert {:ok, hashed_json} = Ruma.add_content_hash_to_event(event_json())

      assert {:ok, hash} = Ruma.reference_hash(hashed_json)

      assert is_binary(hash)
      refute String.contains?(hash, "=")
    end

    test "returns the same hash for the same event" do
      {:ok, hashed_json} = Ruma.add_content_hash_to_event(event_json())

      assert {:ok, hash1} = Ruma.reference_hash(hashed_json)
      assert {:ok, hash2} = Ruma.reference_hash(hashed_json)

      assert hash1 == hash2
    end

    test "returns different hash when content differs" do
      {:ok, hashed_json_a} = Ruma.add_content_hash_to_event(event_json())

      json_b =
        event_json()
        |> Jason.decode!()
        |> put_in(["content", "body"], "different")
        |> Jason.encode!()

      {:ok, hashed_json_b} = Ruma.add_content_hash_to_event(json_b)

      assert {:ok, hash_a} = Ruma.reference_hash(hashed_json_a)
      assert {:ok, hash_b} = Ruma.reference_hash(hashed_json_b)

      refute hash_a == hash_b
    end

    test "produces a different (protocol-incomplete) hash when content hash step is skipped" do
      {:ok, hashed_json} = Ruma.add_content_hash_to_event(event_json())
      {:ok, hash_with_content_hash} = Ruma.reference_hash(hashed_json)

      {:ok, hash_without_content_hash} = Ruma.reference_hash(event_json())

      refute hash_with_content_hash == hash_without_content_hash
    end
  end
end
