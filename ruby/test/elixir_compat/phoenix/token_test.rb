require 'test_helper'

class ElixirCompat::Phoenix::TokenTest < Minitest::Test
  T = ElixirCompat::Phoenix::Token

  def secret
    Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(64), padding: false)[0..64]
  end

  def test_can_sign_and_verify_data
    secret_key_base = secret()
    signed = T.sign(secret_key_base, "salt", "payload")
    result = T.verify(secret_key_base, "salt", signed)
    assert result == "payload"
  end

  def test_can_encrypt_and_decrypt_data
    secret_key_base = secret()
    token = T.encrypt(secret_key_base, "salt", "signing salt", "payload")
    result = T.decrypt(secret_key_base, "salt", "signing salt", token)
    assert result == "payload"
  end

end

