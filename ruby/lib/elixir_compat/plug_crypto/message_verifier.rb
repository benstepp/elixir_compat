require 'base64'

module ElixirCompat
  module PlugCrypto

    ##
    # MessageVerifier makes it easy to generate and verify messages which are
    # signed to prevent tampering.
    #
    # The data can be read by the client, but cannot be tampered with.
    #
    # The message and its verification are base64url encoded and returned to you
    #
    # The current algorithm used is HMAC-SHA, with SHA256, SHA384, and SHA512 as
    # supported digests types.

    class MessageVerifier

      class << self
        ##
        # Signs a message with a given secret
        #
        # ### Parameters
        #
        # * `message` (String) - The message to be signed
        # * `secret` (String) - The secret used when signing
        # * `digest` (Atom) - The digest type to be used. must be one of:
        # `:sha256`, `:sha384`, or `:sha512`.
        #
        # ### Examples
        #
        # ##### Signing a message using the default SHA256 digest type:
        #
        # ```elixir
        # # elixir
        # Plug.Crypto.MessageVerifier.sign("hello world", "secret")
        # ```
        #
        # ```ruby
        # # ruby
        # ElixirCompat::PlugCrypto::MessageVerifier.sign("hello world", "secret")
        # ```
        #
        # ##### Signing a message using another digest type:
        #
        # ```elixir
        # # elixir
        # Plug.Crypto.MessageVerifier.sign("hello world", "secret", :sha512)
        # ```
        #
        # ```ruby
        # # ruby
        # ElixirCompat::PlugCrypto::MessageVerifier.sign("hello world", "secret", :sha512)
        # ```
        #
        def sign(message, secret, digest = :sha256)
          check_message(message)
          hmac_sha2_sign(message, secret, digest)
        end

        ##
        # Decodes and Verfies the encoded binary was not tampered with. This
        # method will raise a
        # `ElixirCompat::PlugCrypto::MessageVerifier::InvalidSignature`
        # whenever the message was not verified.
        #
        # ### Parameters
        #
        # * `signed` (String) - The signed message to be verified
        # * `secret` (String) - The secret used to sign the message
        #
        # ### Examples
        #
        # #### Verifying a signed message
        #
        # ```elixir
        # # elixir
        #
        # signed = "SFMyNTY.aGVsbG8gd29ybGQ.k_zLAG_uMdIoLoQlm7legV0eIm0J2LmyIU4MH-J6at4"
        # {:ok, message} = Plug.Crypto.MessageVerifier.verify(signed, "secret")
        # assert message == "hello world"
        # ```
        #
        # ```ruby
        # # ruby
        #
        # signed = "SFMyNTY.aGVsbG8gd29ybGQ.k_zLAG_uMdIoLoQlm7legV0eIm0J2LmyIU4MH-J6at4"
        # message = ElixirCompat::PlugCrypto::MessageVerifier.verify(signed, "secret")
        # assert message == "hello world"
        # ```
        #
        # #### Error handling comparison
        #
        # ```elixir
        # # elixir
        #
        # signed = "SFMyNTY.aGVsbG8gd29ybGQ.k_zLAG_uMdIoLoQlm7legV0eIm0J2LmyIU4MH-J6at4"
        # case Plug.Crypto.MessageVerifier.verify(signed, "secret") do
        #   {:ok, message} -> message
        #   :error -> # invalid
        # end
        # ```
        #
        # ```ruby
        # # ruby
        #
        # signed = "SFMyNTY.aGVsbG8gd29ybGQ.k_zLAG_uMdIoLoQlm7legV0eIm0J2LmyIU4MH-J6at4"
        # begin
        #   ElixirCompat::PlugCrypto::MessageVerifier.verify(signed, "secret")
        # rescue ElixirCompat::PlugCrypto::MesageVerifier::InvalidSignature
        #   # invalid
        # end
        # ```
        #
        def verify(signed, secret)
          hmac_sha2_verify(signed, secret)
        end

        private

        def hmac_sha2_sign(payload, secret, digest)
          prot = hmac_sha2_to_protected(digest)
          plain_text = signing_input(prot, payload)
          signature = openssl_sign(digest, secret, plain_text)
          "#{plain_text}.#{cast(signature)}"
        end

        def hmac_sha2_verify(signed, secret)
          token = decode_token(signed)
          return nil unless token
          return nil unless ["HS256", "HS384", "HS512"].include?(token[:protected])

          challenge = openssl_sign(hmac_protected_to_sha2(token[:protected]), secret, token[:plain_text])
          if ElixirCompat::PlugCrypto.secure_compare(challenge, token[:signature])
            token[:payload]
          else
            raise InvalidSignature.new
          end
        end

        def decode_token(signed)
          parts = signed.split('.')
          {
            protected: ::Base64.urlsafe_decode64(parts[0]),
            payload: ::Base64.urlsafe_decode64(parts[1]),
            plain_text: "#{parts[0]}.#{parts[1]}",
            signature: ::Base64.urlsafe_decode64(parts[2]),
          }
        rescue
          nil
        end

        def hmac_sha2_to_protected(digest)
          case digest
          when :sha256
            "HS256"
          when :sha384
            "HS384"
          when :sha512
            "HS512"
          else
            raise ArgumentError.new("unknown digest type")
          end
        end

        def hmac_protected_to_sha2(digest)
          case digest
          when "HS256"
            :sha256
          when "HS384"
            :sha384
          when "HS512"
            :sha512
          end
        end

        def hmac_sha2_to_digest_type(digest)
          case digest
          when :sha256
            OpenSSL::Digest::SHA256.new()
          when :sha384
            OpenSSL::Digest::SHA384.new()
          when :sha512
            OpenSSL::Digest::SHA512.new()
          else
            raise ArgumentError.new("unknown digest")
          end
        end

        def signing_input(prot, payload)
          "#{cast(prot)}.#{cast(payload)}"
        end

        def cast(string)
          Base64.urlsafe_encode64(
            string.force_encoding(Encoding::ASCII_8BIT),
            padding: false
          )
        end

        def openssl_sign(digest, key, plain_text)
          digest_type = hmac_sha2_to_digest_type(digest)
          ::OpenSSL::HMAC.digest(digest_type, key, plain_text)
        end

        def check_message(message)
          raise ArgumentError.new("message must be a string") unless message.is_a?(String)
        end

      end

      class InvalidSignature < StandardError; end # :nodoc:

    end
  end
end
