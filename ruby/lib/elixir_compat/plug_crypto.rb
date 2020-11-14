require 'openssl'
require 'elixir_compat/plug_crypto/key_generator'
require 'elixir_compat/plug_crypto/message_verifier'

module ElixirCompat
  module PlugCrypto
    class << self

      def secure_compare(a, b)
        OpenSSL.secure_compare(a, b)
      end

    end
  end
end
