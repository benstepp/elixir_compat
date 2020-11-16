defmodule ElixirCompat.Generator.PlugCrypto do

  @dir "fixtures"

  def run() do
    fixtures()
    |> Enum.map(&build_fixture/1)
    |> write_fixtures()
  end

  def fixtures() do
    [
      %{
        name: "string_uuid",
        secret: secret(),
        salt: salt(),
        signing_salt: salt(),
        payload: UUID.uuid4()
      },
      %{
        name: "integer",
        secret: secret(),
        salt: salt(),
        signing_salt: salt(),
        payload: 69
      }
    ]
  end

  defp build_fixture(fixture) do
    fixture
    |> Map.put(:secret_key_bin64, key(fixture[:secret], fixture[:salt]))
    |> Map.put(:signing_key_bin64, key(fixture[:secret], fixture[:signing_salt]))
    |> Map.put(:payload_bin64, bin64(fixture))
    |> Map.put(:signed, sign(fixture))
    |> Map.put(:encrypted, encrypt(fixture))
    |> Map.delete(:payload)
  end

  defp write_fixtures(fixtures) do
    @dir
    |> Path.join("plug_crypto.json")
    |> File.write!(Jason.encode!(fixtures))
  end

  defp bin64(fixture) do
    fixture
    |> Map.get(:payload)
    |> :erlang.term_to_binary()
    |> Base.encode64()
  end

  defp key(secret, salt) do
    secret
    |> Plug.Crypto.KeyGenerator.generate(salt)
    |> Base.encode64()
  end

  defp sign(%{payload: payload, salt: salt, secret: secret} = _fixture) do
    key = Plug.Crypto.KeyGenerator.generate(secret, salt)
    Plug.Crypto.MessageVerifier.sign(:erlang.term_to_binary(payload), key)
  end

  def encrypt(%{payload: payload, salt: salt, signing_salt: signing_salt, secret: secret} = _fixture) do
    key = Plug.Crypto.KeyGenerator.generate(secret, salt)
    signing_key = Plug.Crypto.KeyGenerator.generate(secret, signing_salt)
    Plug.Crypto.MessageEncryptor.encrypt(:erlang.term_to_binary(payload), key, signing_key)
  end

  def secret() do
    random_string(64)
  end

  def salt() do
    random_string(8)
  end

  defp random_string(length) do
    length
    |> :crypto.strong_rand_bytes()
    |> Base.encode64(padding: false)
    |> binary_part(0, length)
  end

end
