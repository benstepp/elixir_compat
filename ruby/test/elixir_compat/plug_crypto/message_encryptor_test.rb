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
    puts encrypted.inspect
    #result = ME.decrypt(encrypted, SECRET, SECRET)
  end

end
