require 'openssl'

module ElixirCompat
  module PlugCrypto

    ##
    # KeyGenerator implements PBKDF2 (Password-Based Key Derivation Function
    # 2), part of PKCS #5 v2.0 (Password-Based Cryptography Specification).
    #
    # It can be used to derive a number of keys for various purposes from a
    # given secret. This lets applications have a single secure secret, but
    # avoid reusing that key in multiple incompatible contexts.
    #
    # The returned key is a binary. You may invoke functions in the `Base64`
    # module, such as `Base64.urlsafe_encode64`, to convert this binary into a
    # textual representation.
    #
    # see http://tools.ietf.org/html/rfc2898#section-5.2
    module KeyGenerator
      class << self

        DEFAULT_OPTIONS = {
          iterations: 1000,
          length: 32,
          digest: :sha256
        } # :nodoc:

        MAX_LENGTH = (1 << 32) - 1 # :nodoc:

        ##
        # Generates a derived key suitable for use.
        #
        # ### Parameters
        #
        # * `secret` (String) - The single secret used. This is typically
        # generated with `mix phx.gen.secret` in your elixir application
        # * `salt` (String) - Salt used to generate a key.
        # * `options` (Hash) - A hash of options used to generate the key.
        #
        # #### Options
        #
        # * `iterations` (Integer) - Default of 1000 (increase to at least 2^16 for passwords)
        # * `length` (Integer) - A length in octets for the derived key (defaults to 32)
        # * `digest` (Atom) - The digest type to be used for the pseudo random
        # function. Allowed values include: `:sha`, `:sha1`, `:sha224`,
        # `:sha256`, `:sha384`, or `:sha512`.
        #
        # ### Examples
        #
        # #### Generating a Key with salt
        #
        # ```elixir
        # # elixir
        #
        # secret = Application.get_env(:my_app, :secret_key_base)
        # Plug.Crypto.KeyGenerator.generate(secret, "salt")
        # ```
        #
        # ```ruby
        # # ruby
        #
        # secret = Rails.application.secrets.secret_key_base
        # ElixirCompat::PlugCrypto::KeyGenerator.generate(secret, "salt")
        # ```
        #
        #
        def generate(secret, salt, options = {})
          options = DEFAULT_OPTIONS.merge(options)
          check_iterations(options)
          check_length(options)
          openssl_generate(secret, salt, options)
        end

        private

        def openssl_generate(secret, salt, options)
          OpenSSL::PKCS5.pbkdf2_hmac(secret, salt, options[:iterations], options[:length], digest(options[:digest]))
        end

        def check_iterations(options)
          iterations = options[:iterations]
          raise ArgumentError.new("iterations must be an integer") unless iterations.is_a?(Integer)
          raise ArgumentError.new("iterations must be >= 1") unless iterations >= 1
        end

        def check_length(options)
          length = options[:length]
          raise ArgumentError.new("length must be an integer") unless length.is_a?(Integer)
          raise ArgumentError.new("length must be >= 1") unless length >= 1
          raise ArgumentError.new("length must be less than or equal to #{MAX_LENGTH}") if length > MAX_LENGTH
        end

        def digest(digest_long_name)
          case digest_long_name
          when :sha
            OpenSSL::Digest::SHA1.new()
          when :sha1
            OpenSSL::Digest::SHA1.new()
          when :sha224
            OpenSSL::Digest::SHA224.new()
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

      end
    end
  end
end
