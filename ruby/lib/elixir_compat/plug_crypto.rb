require 'openssl'
require 'elixir_compat/plug_crypto/key_generator'
require 'elixir_compat/plug_crypto/message_encryptor'
require 'elixir_compat/plug_crypto/message_verifier'

module ElixirCompat
  ##
  # Ruby module that is mostly compatible with `Plug.Crypto` in elixir
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

    end
  end
end
