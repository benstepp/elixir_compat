require 'test_helper'

class ElixirCompat::PlugCryptoTest < Minitest::Test
  PC = ElixirCompat::PlugCrypto

  def secret
    Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(64), padding: false)[0..64]
  end

  def test_masks_tokens
    assert PC.mask(0b0101, 0b0110) == 0b0011
    assert PC.mask(0b0011, 0b0110) == 0b0101
  end

  def test_compares_binaries_securly
    assert PC.secure_compare("a", "a")
    assert PC.secure_compare("1", "1")
    assert PC.secure_compare("69", "69")
    refute PC.secure_compare("0", "1")
    refute PC.secure_compare("1", "0")
    refute PC.secure_compare("0", "1111111")
  end

  def test_can_sign_and_verify_string
    secret_key_base = secret()
    signed = PC.sign(secret_key_base, "salt", "lol")
    result = PC.verify(secret_key_base, "salt", signed)
    assert result == "lol"
  end

  def test_can_sign_and_verify_integer
    secret_key_base = secret()
    signed = PC.sign(secret_key_base, "salt", 69)
    result = PC.verify(secret_key_base, "salt", signed)
    assert result == 69
  end

  def test_can_sign_and_verify_data
    data = [0, 1, 2, 3]
    secret_key_base = secret()
    signed = PC.sign(secret_key_base, "salt", data)
    result = PC.verify(secret_key_base, "salt", signed)
    assert result == data
  end

  def test_sign_and_verify_can_error_when_token_change
    data = [0, 1, 2, 3]
    secret_key_base = secret()
    signed = PC.sign(secret_key_base, "salt", data)
    assert_raises PC::Error do
      PC.verify(secret_key_base, "pepper", signed)
    end
  end

  def test_sign_and_verify_supports_max_age_in_seconds
    secret_key_base = secret()
    signed = PC.sign(secret_key_base, "salt", "test message")
    assert PC.verify(secret_key_base, "salt", signed, max_age: 1000)
    assert PC.verify(secret_key_base, "salt", signed, max_age: 100)

    assert_raises PC::Error do
      PC.verify(secret_key_base, "salt", signed, max_age: -1000)
    end

    assert_raises PC::Error do
      PC.verify(secret_key_base, "salt", signed, max_age: -100)
    end
  end

  def test_sign_and_verify_supports_max_age_on_signing
    secret_key_base = secret()
    signed = PC.sign(secret_key_base, "salt", "test message", max_age: -100)

    assert_raises PC::Error do
      PC.verify(secret_key_base, "salt", signed)
    end
  end

  def test_sign_and_verify_supports_max_age_infinity
    secret_key_base = secret()
    signed = PC.sign(secret_key_base, "salt", "test message")
    assert PC.verify(secret_key_base, "salt", signed, max_age: :infinity)
  end

  def test_sign_and_verify_passes_key_iterations_to_key_generator
    secret_key_base = secret()
    signed_a = PC.sign(secret_key_base, "salt", "test message", key_iterations: 1)
    signed_b = PC.sign(secret_key_base, "salt", "test message", key_iterations: 2)
    assert signed_a != signed_b
  end

  def test_sign_and_verify_passes_key_length_to_key_generator
    secret_key_base = secret()
    signed_a = PC.sign(secret_key_base, "salt", "test message", key_length: 32)
    signed_b = PC.sign(secret_key_base, "salt", "test message", key_length: 64)
    assert signed_a != signed_b
  end

  def test_sign_and_verify_passes_key_digest_to_key_generator
    secret_key_base = secret()
    signed_a = PC.sign(secret_key_base, "salt", "test message", key_digest: :sha256)
    signed_b = PC.sign(secret_key_base, "salt", "test message", key_digest: :sha512)
    assert signed_a != signed_b
  end

  def test_sign_and_verify_key_default_parameters
    secret_key_base = secret()
    default_options = {
      key_iterations: 1000,
      key_legnth: 32,
      key_digest: :sha256,
      signed_at: 0
    }
    signed_a = PC.sign(secret_key_base, "salt", "test message", signed_at: 0)
    signed_b = PC.sign(secret_key_base, "salt", "test message", default_options)
    assert signed_a == signed_b
  end

  def test_can_encrypt_and_decrypt_string
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "string")
    result = PC.decrypt(secret_key_base, "salt", "signing salt", token)
    assert result == "string"
  end

  def test_decrypt_errors_when_secret_changes
    token = PC.encrypt(secret(), "salt", "signing salt", "string")

    assert_raises PC::Error do
      PC.decrypt(secret(), "salt", "signing salt", token)
    end
  end

  def test_decrypt_errors_when_salt_changes
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "string")

    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt2", "signing salt", token)
    end
  end

  def test_decrypt_errors_when_signing_salt_changes
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "string")

    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt", "signing salt 2", token)
    end
  end

  def test_decrypt_supports_max_age
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "string")

    assert PC.decrypt(secret_key_base, "salt", "signing salt", token, max_age: 1000)
    assert PC.decrypt(secret_key_base, "salt", "signing salt", token, max_age: 100)

    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt", "signing salt", token, max_age: -1000)
    end

    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt", "signing salt", token, max_age: -100)
    end
  end

  def test_encrypt_supports_max_age
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "string", max_age: 1000)
    assert PC.decrypt(secret_key_base, "salt", "signing salt", token)

    token = PC.encrypt(secret_key_base, "salt", "signing salt", "string", max_age: -1000)

    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt", "signing salt", token)
    end
  end

  def test_encrypt_supports_infinity
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "string")
    assert PC.decrypt(secret_key_base, "salt", "signing salt", token, max_age: :infinity)
  end

  def test_encrypt_passes_key_iterations_to_key_generator
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "message", key_iterations: 1)

    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt", "signing salt", token, key_iterations: 2)
    end
  end

  def test_encrypt_passes_key_length_to_key_generator
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "message", key_length: 32)

    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt", "signing salt", token, key_length: 64)
    end
  end

  def test_encrypt_passes_key_digest_to_key_generator
    secret_key_base = secret()
    token = PC.encrypt(secret_key_base, "salt", "signing salt", "message", key_digest: :sha256)
    assert_raises PC::Error do
      PC.decrypt(secret_key_base, "salt", "signing salt", token, key_digest: :sha512)
    end
  end

end
