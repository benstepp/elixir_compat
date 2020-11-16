require 'test_helper'
require 'json'

class ElixirCompat::PlugCrypto::FixturesTest < Minitest::Test
  ElixirCompat::Fixtures.load('plug_crypto').each do |fixture|

    define_method(:"test_#{fixture[:name]}_secret_key_is_same") do
      key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:salt])
      assert key == Base64.decode64(fixture[:secret_key_bin64])
    end

    define_method(:"test_#{fixture[:name]}_signing_key_is_same") do
      key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:signing_salt])
      assert key == Base64.decode64(fixture[:signing_key_bin64])
    end

    define_method(:"test_#{fixture[:name]}_signed_message_is_same") do
      key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:salt])
      bin = Base64.decode64(fixture[:payload_bin64])
      signed = ElixirCompat::PlugCrypto::MessageVerifier.sign(bin, key)
      assert signed == fixture[:signed]
    end

    define_method(:"test_#{fixture[:name]}_signed_message_can_be_verified") do
      key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:salt])
      result = ElixirCompat::PlugCrypto::MessageVerifier.verify(fixture[:signed], key)
      assert result == Base64.decode64(fixture[:payload_bin64])
    end

    define_method(:"test_#{fixture[:name]}_signed_message_can_be_verified_and_repacked") do
      key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:salt])
      result = ElixirCompat::PlugCrypto::MessageVerifier.verify(fixture[:signed], key)
      signed = ElixirCompat::PlugCrypto::MessageVerifier.sign(result, key)
      assert signed == fixture[:signed]
    end

    define_method(:"test_#{fixture[:name]}_can_decrypt_message") do
      key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:salt])
      signing_key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:signing_salt])
      bin = Base64.decode64(fixture[:payload_bin64])

      result = ElixirCompat::PlugCrypto::MessageEncryptor.decrypt(fixture[:encrypted], key, signing_key)
      assert result == bin
    end

    define_method(:"test_#{fixture[:name]}_can_encrypt_and_decrypt_message") do
      key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:salt])
      signing_key = ElixirCompat::PlugCrypto::KeyGenerator.generate(fixture[:secret], fixture[:signing_salt])
      bin = Base64.decode64(fixture[:payload_bin64])

      encrypted = ElixirCompat::PlugCrypto::MessageEncryptor.encrypt(bin, key, signing_key)
      result = ElixirCompat::PlugCrypto::MessageEncryptor.decrypt(encrypted, key, signing_key)
      assert result == bin
    end

  end
end
