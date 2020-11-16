require 'openssl'
require 'elixir_compat/plug_crypto/key_generator'
require 'elixir_compat/plug_crypto/message_encryptor'
require 'elixir_compat/plug_crypto/message_verifier'

module ElixirCompat
  ##
  # ElixirCompat::PlugCrypto is a ruby module that aims to be compatible with
  # the library `Plug.Crypto` written in elixir.
  #
  # ##### Plug.Crypto External Links
  # * [hex.pm](https://hex.pm/packages/plug_crypto)
  # * [hexdocs](https://hexdocs.pm/plug_crypto/Plug.Crypto.html)
  # * [github](https://github.com/elixir-plug/plug_crypto)
  #
  module PlugCrypto
    class << self

      ##
      # Compares the two binaries in constant-time to avoid timing attacks.
      #
      def secure_compare(a, b)
        OpenSSL.secure_compare(a, b)
      end

      ##
      # Masks the token on the left with the token on the right.
      #
      # Both tokens are required to have the same size.
      #
      def mask(a, b)
        a ^ b
      end

      ##
      # Encodes and signs data into a token
      #
      # ### Parameters
      # * `secret_key_base` (String) - The secret key base used to generate a key
      # * `salt` (String) - The salt used to generate the key
      # * `data` (Any) - The data to be encoded into the token. This uses
      # Erlang.term_to_binary interally
      #
      # #### Options
      #
      # * `key_iterations` (Integer) - Default of 1000 (increase to at least 2^16 for passwords)
      # * `key_length` (Integer) - A length in octets for the derived key (defaults to 32)
      # * `key_digest` (Atom) - The digest type to be used for the pseudo random
      # function. Allowed values include: `:sha`, `:sha1`, `:sha224`,
      # `:sha256`, `:sha384`, or `:sha512`.
      # * `signed_at` (Integer) - The timestamp of when the token was signed,
      # defaults to Time.now.to_i
      # * `max_age` - The default maximum age of the token. Defaults to `86400`
      # seconds (1 day).
      #
      # ### Examples
      #
      # #### Signing a message
      #
      # ```elixir
      # # elixir
      # secret_key_base = Application.get_env(:my_app, :secret_key_base)
      # Plug.Crypto.sign(secret_key_base, "salt", "message")
      # ```
      #
      # ```ruby
      # # ruby
      # secret_key_base = Rails.application.secrets.secret_key_base
      # ElixirCompat::PlugCrypto.sign(secret_key_base, "salt", "message")
      # ```
      #
      #
      def sign(secret_key_base, salt, data, options = {})
        encoded = encode(data, options)
        key = get_secret(secret_key_base, salt, options)
        MessageVerifier.sign(encoded, key)
      end

      ##
      # Decodes the original token created with #sign and verifies it's
      # integrity.
      #
      # ### Parameters
      # * `secret_key_base` (String) - The secret key base used to generate a key
      # * `salt` (String) - The salt used to generate the key
      # * `token` (Any) - The token created with #sign
      #
      # #### Options
      # * `key_iterations` (Integer) - Default of 1000 (increase to at least 2^16 for passwords)
      # * `key_length` (Integer) - A length in octets for the derived key (defaults to 32)
      # * `key_digest` (Atom) - The digest type to be used for the pseudo random
      # function. Allowed values include: `:sha`, `:sha1`, `:sha224`,
      # `:sha256`, `:sha384`, or `:sha512`.
      # * `max_age` - The default maximum age of the token. Defaults to `86400`
      # seconds (1 day).
      #
      # ### Examples
      #
      # #### Verifying a message
      #
      # ```elixir
      # # elixir
      # secret_key_base = Application.get_env(:my_app, :secret_key_base)
      # token = "SFMyNTY.aGVsbG8gd29ybGQ.k_zLAG_uMdIoLoQlm7legV0eIm0J2LmyIU4MH-J6at4"
      # Plug.Crypto.verify(secret_key_base, "salt", token)
      # ```
      #
      # ```ruby
      # # ruby
      # secret_key_base = Rails.application.secrets.secret_key_base
      # token = "SFMyNTY.aGVsbG8gd29ybGQ.k_zLAG_uMdIoLoQlm7legV0eIm0J2LmyIU4MH-J6at4"
      # ElixirCompat::PlugCrypto.verify(secret_key_base, "salt", token)
      # ```
      #
      def verify(secret_key_base, salt, token, options = {})
        key = get_secret(secret_key_base, salt, options)
        encoded = MessageVerifier.verify(token, key)
        decode(encoded, options)
      end

      ##
      # Encodes, encrypts, and signs data into a token
      #
      # :args: secret_key_base, salt, signing_salt, data, options = {}
      #
      # ### Parameters
      # * `secret_key_base` (String) - The secret key base used to generate a key
      # * `salt` (String) - The salt used to generate the key
      # * `signing_salt` (String) [optional] - The salt used to sign the content encryption key
      # * `data` (Any) - The data to be encoded into the token. This uses
      #
      # #### Options
      # * `key_iterations` (Integer) - Default of 1000 (increase to at least 2^16 for passwords)
      # * `key_length` (Integer) - A length in octets for the derived key (defaults to 32)
      # * `key_digest` (Atom) - The digest type to be used for the pseudo random
      # function. Allowed values include: `:sha`, `:sha1`, `:sha224`,
      # `:sha256`, `:sha384`, or `:sha512`.
      # * `max_age` - The default maximum age of the token. Defaults to `86400`
      # seconds (1 day).
      #
      # ### Examples
      #
      # #### Encrypting some data
      #
      # ```elixir
      # # elixir
      # secret_key_base = Application.get_env(:my_app, :secret_key_base)
      # Plug.Crypto.encrypt(secret_key_base, "salt", "signing salt", "message")
      # ```
      #
      # ```ruby
      # # ruby
      # secret_key_base = Rails.application.secrets.secret_key_base
      # ElixirCompat::PlugCrypto.encrypt(secret_key_base, "salt", "signing salt", "message")
      # ```
      #
      def encrypt(secret_key_base, salt, *args)
        case args.length
        when 1
          _encrypt(secret_key_base, salt, "", args[0], {})
        when 2
          if probably_options(args[1])
            _encrypt(secret_key_base, salt, "", args[0], args[1])
          else
            _encrypt(secret_key_base, salt, args[0], args[1], {})
          end
        when 3
          _encrypt(secret_key_base, salt, args[0], args[1], args[2])
        end
      end

      ##
      # Decrypts and verifies a token that was generated with #encyrpt
      #
      # :args: secret_key_base, salt, signing_salt, token, options = {}
      #
      # ### Parameters
      # * `secret_key_base` (String) - The secret key base used to generate a key
      # * `salt` (String) - The salt used to generate the key
      # * `signing_salt` (String) [optional] - The salt used to sign the content encryption key
      # * `token` (String) - The token created with #encrypt
      #
      # #### Options
      # * `key_iterations` (Integer) - Default of 1000 (increase to at least 2^16 for passwords)
      # * `key_length` (Integer) - A length in octets for the derived key (defaults to 32)
      # * `key_digest` (Atom) - The digest type to be used for the pseudo random
      # function. Allowed values include: `:sha`, `:sha1`, `:sha224`,
      # `:sha256`, `:sha384`, or `:sha512`.
      # * `max_age` - The default maximum age of the token. Defaults to `86400`
      # seconds (1 day).
      #
      # ### Examples
      #
      # #### Decrypting a token
      #
      # ```elixir
      # # elixir
      # secret_key_base = Application.get_env(:my_app, :secret_key_base)
      # token = "QTEyOEdDTQ.m2ldzZE0r-p4MXyBMQ_--wf23dSGBst37wkX-w9_Xd98KYQx3_z3Dst_Vyo.Z-vWtDbblZXGJ_p5.wAz3NhV3to7Uu8osM_9Qi5zd7uTY_oDaQgIjcSaLhIvNDG-isG4BPSvD.rH8q5cE5ECOszOwrI0rnTA"
      # Plug.Crypto.decrypt(secret_key_base, "salt", "signing salt", token)
      # ```
      #
      # ```ruby
      # # ruby
      # secret_key_base = Rails.application.secrets.secret_key_base
      # token = "QTEyOEdDTQ.m2ldzZE0r-p4MXyBMQ_--wf23dSGBst37wkX-w9_Xd98KYQx3_z3Dst_Vyo.Z-vWtDbblZXGJ_p5.wAz3NhV3to7Uu8osM_9Qi5zd7uTY_oDaQgIjcSaLhIvNDG-isG4BPSvD.rH8q5cE5ECOszOwrI0rnTA"
      # ElixirCompat::PlugCrypto.decrypt(secret_key_base, "salt", "signing salt", token)
      # ```
      #
      def decrypt(secret_key_base, salt, *args)
        case args.length
        when 1
          _decrypt(secret_key_base, salt, "", args[0], {})
        when 2
          if probably_options(args[1])
            _decrypt(secret_key_base, salt, "", args[0], args[1])
          else
            _decrypt(secret_key_base, salt, args[0], args[1], {})
          end
        when 3
          _decrypt(secret_key_base, salt, args[0], args[1], args[2])
        end
      end

      private

      def _encrypt(secret_key_base, salt, signing_salt, data, options = {})
        encoded = encode(data, options)
        key = get_secret(secret_key_base, salt, options)
        signing_key = get_secret(secret_key_base, signing_salt, options)
        MessageEncryptor.encrypt(encoded, key, signing_key)
      end

      def _decrypt(secret_key_base, salt, signing_salt, token, options = {})
        key = get_secret(secret_key_base, salt, options)
        signing_key = get_secret(secret_key_base, signing_salt, options)
        encoded = MessageEncryptor.decrypt(token, key, signing_key)
        decode(encoded, options)
      end

      def encode(data, options)
        if options[:signed_at]
          signed_at_ms = options[:signed_at] * 1000
        else
          signed_at_ms = Time.now.to_i
        end

        max_age_in_seconds = options[:max_age] || 86400

        Erlang::TAG_VERSION.chr + Erlang.tuple_to_binary([
          data,
          signed_at_ms,
          max_age_in_seconds
        ])
      end

      def decode(encoded, options)
        payload = backwards_compatible_decode(encoded)

        if expired?(payload[1], options[:max_age] || payload[2])
          raise Error.new(:expired)
        else
          payload[0]
        end
      end

      def expired?(signed_at, max_age)
        return false if max_age == :infinity
        return true if max_age <= 0
        (signed_at + (max_age * 1000)) > (Time.now.to_i * 1000)
      end

      def backwards_compatible_decode(encoded)
        payload = Erlang.binary_to_term(encoded)
        case payload
        when Array
          if payload.length == 2
            [payload[0], payload[1], 86400]
          else
            [payload[0], payload[1], payload[2]]
          end
        when Hash
          [payload[:data], payload[:signed], 86400]
        end
      end

      def probably_options(arg)
        option_keys = [:key_iterations, :key_length, :key_digest, :max_age, :signed_at]
        return false unless arg.is_a?(Hash)
        return arg.keys.any? { |k| option_keys.include?(k) }
      end

      def get_secret(secret_key_base, salt, options)
        options = {
          iterations: options[:key_iterations] || 1000,
          length: options[:key_length] || 32,
          digest: options[:key_digest] || :sha256
        }
        KeyGenerator.generate(secret_key_base, salt, options)
      end

    end

    class Error < StandardError; end # :nodoc:
  end
end
