require 'test_helper'

class ElixirCompat::PlugCrypto::MessageVerifierTest < Minitest::Test
  MV = ElixirCompat::PlugCrypto::MessageVerifier

  def test_sign_errors_when_message_is_not_a_string
    assert_raises ArgumentError do
      MV.sign(nil, "secret")
    end
  end

  def test_sign_errors_when_unknown_digest
    assert_raises ArgumentError do
      MV.sign("message", "secret", :sha9001)
    end
  end

  def test_sign_generates_a_signed_message_using_sha256
    signed = MV.sign("hello world", "secret")
    assert Base64.urlsafe_decode64(parts(signed)[:protected]) == "HS256"
    assert Base64.urlsafe_decode64(parts(signed)[:payload]) == "hello world"
    assert parts(signed)[:signature].bytesize == 43
  end

  def test_sign_generates_a_signed_message_using_sha384
    signed = MV.sign("hello world", "secret", :sha384)
    assert Base64.urlsafe_decode64(parts(signed)[:protected]) == "HS384"
    assert Base64.urlsafe_decode64(parts(signed)[:payload]) == "hello world"
    assert parts(signed)[:signature].bytesize == 64
  end

  def test_sign_generates_a_signed_message_using_sha512
    signed = MV.sign("hello world", "secret", :sha512)
    assert Base64.urlsafe_decode64(parts(signed)[:protected]) == "HS512"
    assert Base64.urlsafe_decode64(parts(signed)[:payload]) == "hello world"
    assert parts(signed)[:signature].bytesize == 86
  end

  def test_verifys_a_signed_message_using_sha256
    signed = MV.sign("hello world", "secret")
    assert MV.verify(signed, "secret") == "hello world"
  end

  def test_verifys_a_signed_message_using_sha384
    signed = MV.sign("hello world", "secret", :sha384)
    assert MV.verify(signed, "secret") == "hello world"
  end

  def test_verifys_a_signed_message_using_sha512
    signed = MV.sign("hello world", "secret", :sha512)
    assert MV.verify(signed, "secret") == "hello world"
  end

  def test_verify_errors_when_secret_changed_using_sha256
    signed = MV.sign("hello world", "secret")

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(signed, "newsecret")
    end
  end

  def test_verify_errors_when_secret_changed_using_sha384
    signed = MV.sign("hello world", "secret", :sha384)

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(signed, "newsecret")
    end
  end

  def test_verify_errors_when_secret_changed_using_sha512
    signed = MV.sign("hello world", "secret", :sha512)

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(signed, "newsecret")
    end
  end

  def test_verify_errors_when_payload_tampered_using_sha256
    signed = MV.sign("hello world", "secret")
    parts = signed.split(".")
    parts[1] = Base64.urlsafe_encode64("hello mars", padding: false)
    tampered = parts.join(".")

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(tampered, "secret")
    end
  end

  def test_verify_errors_when_payload_tampered_using_sha384
    signed = MV.sign("hello world", "secret", :sha384)
    parts = signed.split(".")
    parts[1] = Base64.urlsafe_encode64("hello mars", padding: false)
    tampered = parts.join(".")

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(tampered, "secret")
    end
  end

  def test_verify_errors_when_payload_tampered_using_sha512
    signed = MV.sign("hello world", "secret", :sha512)
    parts = signed.split(".")
    parts[1] = Base64.urlsafe_encode64("hello mars", padding: false)
    tampered = parts.join(".")

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(tampered, "secret")
    end
  end

  def test_verify_errors_when_protected_tampered_using_sha256
    signed = MV.sign("hello world", "secret")
    parts = signed.split(".")
    parts[0] = Base64.urlsafe_encode64("HS384", padding: false)
    tampered = parts.join(".")

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(tampered, "secret")
    end
  end

  def test_verify_errors_when_protected_tampered_using_sha384
    signed = MV.sign("hello world", "secret", :sha384)
    parts = signed.split(".")
    parts[0] = Base64.urlsafe_encode64("HS512", padding: false)
    tampered = parts.join(".")

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(tampered, "secret")
    end
  end

  def test_verify_errors_when_protected_tampered_using_sha512
    signed = MV.sign("hello world", "secret", :sha512)
    parts = signed.split(".")
    parts[0] = Base64.urlsafe_encode64("HS256", padding: false)
    tampered = parts.join(".")

    assert_raises ElixirCompat::PlugCrypto::Error do
      MV.verify(tampered, "secret")
    end
  end

  def parts(string)
    p = string.split(".")
    {
      protected: p[0],
      payload: p[1],
      signature: p[2]
    }
  end

end
