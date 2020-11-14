require 'openssl'

module ElixirCompat
  module PlugCrypto
    module KeyGenerator
      class << self

        DEFAULT_OPTIONS = {
          iterations: 1000,
          length: 32,
          digest: :sha256
        }

        MAX_LENGTH = (1 << 32) - 1

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
          when :sha348
            OpenSSL::Digest::SHA348.new()
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
