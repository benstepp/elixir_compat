require 'elixir_compat/plug_crypto'

module ElixirCompat
  module Phoenix
    ##
    # Tokens provide a way to generate and verify bearer
    # tokens for use in Channels or API authentication.
    #
    # The data stored in the token is signed to prevent tampering
    # but not encrypted. This means it is safe to store identification
    # information (such as user IDs) but should not be used to store
    # confidential information (such as credit card numbers).
    #
    # ## Compatibility Notice
    #
    # In phoenix, you can pass a `Plug.Conn` `Phoenix.Socket`
    # `Phoenix.Endpoint` or a binary string of the secret_key_base. **This
    # library only supports directly passing the secret_key_base as a string.**
    #
    class Token
      class << self

        ##
        # Encodes and signs data into a token.
        #
        # See ElixirCompat::PlugCrypto.sign for a complete list of options
        # and examples.
        #
        # :args: secret_key-base, salt, data, options = {}
        def sign(*args)
          ElixirCompat::PlugCrypto.sign(*args)
        end

        ##
        # Decodes the original token created with #sign and verifies it's
        # integrity.
        #
        # See ElixirCompat::PlugCrypto.verify for a complete list of options
        # and examples.
        #
        # :args: secret_key_base, salt, token, options = {}
        #
        def verify(*args)
          ElixirCompat::PlugCrypto.verify(*args)
        end

        ##
        # Encodes, encrypts, and signs data into a token.
        #
        # See ElixirCompat::PlugCrypto.encrypt for a complete list of options
        # and examples.
        #
        # :args: secret_key_base, salt, signing_salt, data, options = {}
        #
        def encrypt(*args)
          ElixirCompat::PlugCrypto.encrypt(*args)
        end

        ##
        # Decrypts and verifies a token.
        #
        # See ElixirCompat::PlugCrypto.decrypt for a complete list of options
        # and examples.
        #
        # :args: secret_key_base, salt, signing_salt, token, options = {}
        #
        def decrypt(*args)
          ElixirCompat::PlugCrypto.decrypt(*args)
        end

      end
    end
  end
end
