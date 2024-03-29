require 'test_helper'
require 'securerandom'

class ElixirCompat::PlugCrypto::MessageEncryptorTest < Minitest::Test
  ME = ElixirCompat::PlugCrypto::MessageEncryptor

  BINARY = " hełłoworld ".force_encoding(Encoding::ASCII_8BIT)
  SECRET = SecureRandom.hex(32)

  def test_errors_when_byte_size_of_secret_isnt_a_string
    assert_raises ArgumentError do
      ME.encrypt(BINARY, 123.45, SECRET)
    end
  end

  def test_errors_when_byte_size_of_secret_is_0
    assert_raises ArgumentError do
      ME.encrypt(BINARY, "", SECRET)
    end
  end

  def test_errors_when_signing_secret_isnt_a_string
    assert_raises ArgumentError do
      ME.encrypt(BINARY, SECRET, 42)
    end
  end

  def test_can_encrypt_and_decrypt_a_message
    encrypted = ME.encrypt(BINARY, SECRET, SECRET)
    result = ME.decrypt(encrypted, SECRET, SECRET)
    assert result == BINARY
  end

  def test_errors_when_secret_is_wrong
    encrypted = ME.encrypt(BINARY, SECRET, SECRET)
    assert_raises ElixirCompat::PlugCrypto::Error do
      ME.decrypt(encrypted, SecureRandom.hex(32), SECRET)
    end
  end

  def test_errors_when_signing_secret_is_wrong
    encrypted = ME.encrypt(BINARY, SECRET, SECRET)
    assert_raises ElixirCompat::PlugCrypto::Error do
      ME.decrypt(encrypted, SECRET, SecureRandom.hex(32))
    end
  end

  def test_errors_when_both_secrets_are_wrong
    encrypted = ME.encrypt(BINARY, SECRET, SECRET)
    assert_raises ElixirCompat::PlugCrypto::Error do
      ME.decrypt(encrypted, SecureRandom.hex(32), SecureRandom.hex(32))
    end
  end

  def test_encrypts_with_only_first_32_bytes_of_secret
    large_secret = SECRET + SECRET
    encrypted = ME.encrypt(BINARY, large_secret, SECRET)
    assert BINARY == ME.decrypt(encrypted, SECRET, SECRET)
    assert BINARY == ME.decrypt(encrypted, large_secret, SECRET)
    assert_raises ElixirCompat::PlugCrypto::Error do
      ME.decrypt(encrypted, SECRET, large_secret)
    end
    assert_raises ElixirCompat::PlugCrypto::Error do
      ME.decrypt(encrypted, large_secret, large_secret)
    end
  end

  def test_encrypts_with_only_first_32_bytes_of_secret_with_large_signing_secret
    large_secret = SECRET + SECRET
    encrypted = ME.encrypt(BINARY, large_secret, large_secret)
    assert BINARY == ME.decrypt(encrypted, SECRET, large_secret)
    assert BINARY == ME.decrypt(encrypted, large_secret, large_secret)
    assert_raises ElixirCompat::PlugCrypto::Error do
      ME.decrypt(encrypted, SECRET, SECRET)
    end
    assert_raises ElixirCompat::PlugCrypto::Error do
      ME.decrypt(encrypted, large_secret, SECRET)
    end
  end

end
