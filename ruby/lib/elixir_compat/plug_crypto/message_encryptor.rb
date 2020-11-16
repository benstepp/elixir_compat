require 'openssl'
require 'erlang'

module ElixirCompat
  module PlugCrypto
    ##
    # stuff
    class MessageEncryptor
      class << self

        ##
        # Encrypts a message
        #
        def encrypt(message, secret, signing_secret)
          check_secret(secret)
          check_signing_secret(signing_secret)

          secret = secret[0..31] if secret.bytesize > 32
          aes128_gcm_encrypt(message, secret, signing_secret)
        end

        def decrypt(encrypted, secret, signing_secret)
          check_secret(secret)
          check_signing_secret(signing_secret)

          secret = secret[0..31] if secret.bytesize > 32
          aes128_gcm_decrypt(encrypted, secret, signing_secret)
        end

        private

        def check_secret(secret)
          raise ArgumentError.new("secret must be a string") unless secret.is_a?(String)
          raise ArgumentError.new("secret must have byte_size > 0") unless secret.bytesize > 0
        end

        def check_signing_secret(secret)
          raise ArgumentError.new("signing_secret must be a string") unless secret.is_a?(String)
        end

        def aes128_gcm_encrypt(plain_text, secret, signing_secret)
          key = OpenSSL::Random.random_bytes(16)
          iv = OpenSSL::Random.random_bytes(12)
          aad = "A128GCM"
          cipher = block_encrypt(key, iv, aad, plain_text)
          encrypted_key = aes_gcm_key_wrap(key, secret, signing_secret)
          encode_token(aad, encrypted_key, iv, cipher[:text], cipher[:tag])
        end

        def encode_token(protectedd, encrypted_key, iv, cipher_text, cipher_tag)
          [
            Base64.urlsafe_encode64(protectedd, padding: false),
            Base64.urlsafe_encode64(encrypted_key, padding: false),
            Base64.urlsafe_encode64(iv, padding: false),
            Base64.urlsafe_encode64(cipher_text, padding: false),
            Base64.urlsafe_encode64(cipher_tag, padding: false),
          ].join(".")
        end

        def block_encrypt(key, iv, aad, payload)
          if key.bytesize == 32
            cipher = OpenSSL::Cipher.new('aes-256-gcm')
          elsif  key.bytesize == 16
            cipher = OpenSSL::Cipher.new('aes-128-gcm')
          end
          cipher.encrypt
          cipher.iv = iv
          cipher.key = key
          cipher.auth_data = aad
          {
            text: cipher.update(payload) + cipher.final,
            tag: cipher.auth_tag(16)
          }
        end

        def block_decrypt(key, iv, aad, cipher_text, cipher_tag)
          if key.bytesize == 32
            cipher = OpenSSL::Cipher.new('aes-256-gcm')
          elsif  key.bytesize == 16
            cipher = OpenSSL::Cipher.new('aes-128-gcm')
          end
          cipher.decrypt
          cipher.iv = iv
          cipher.key = key
          cipher.auth_data = aad
          cipher.auth_tag = cipher_tag
          cipher.update(cipher_text) + cipher.final
        rescue
          raise InvalidMessage.new()
        end

        def aes_gcm_key_wrap(cek, secret, signing_secret)
          iv = OpenSSL::Random.random_bytes(12)
          cipher = block_encrypt(secret, iv, signing_secret, cek)
          cipher[:text] + cipher[:tag] + iv
        end

        def aes_gcm_key_unwrap(wrapped_cek, secret, signing_secret)
          case wrapped_cek.bytesize
          when 44
            cipher_text = wrapped_cek.byteslice(0, 16)
            cipher_tag = wrapped_cek.byteslice(16, 16)
            iv = wrapped_cek.byteslice(32, 44)
            block_decrypt(secret, iv, signing_secret, cipher_text, cipher_tag)
          when 52
            cipher_text = wrapped_cek.byteslice(0, 24)
            cipher_tag = wrapped_cek.byteslice(24, 16)
            iv = wrapped_cek.byteslice(40, 52)
            block_decrypt(secret, iv, signing_secret, cipher_text, cipher_tag)
          when 60
            cipher_text = wrapped_cek.byteslice(0, 32)
            cipher_tag = wrapped_cek.byteslice(32, 16)
            iv = wrapped_cek.byteslice(48, 60)
            block_decrypt(secret, iv, signing_secret, cipher_text, cipher_tag)
          else
            raise InvalidMessage.new()
          end
        end

        def aes128_gcm_decrypt(encrypted, secret, signing_secret)
          parts = decode_token(encrypted)
          check_parts(parts)
          key = aes_gcm_key_unwrap(parts[1], secret, signing_secret)
          block_decrypt(key, parts[2], parts[0], parts[3], parts[4])
        end

        def decode_token(encrypted)
          encrypted
            .split(".")
            .map { |p| Base64.urlsafe_decode64(p) }
        end

        def check_parts(parts)
          raise InvalidMessage.new() unless parts[0] == "A128GCM"
        end

        def bitsize(string)
          string.unpack("B*")[0].length
        end

      end

      class InvalidMessage < StandardError; end # :nodoc:

    end
  end
end
