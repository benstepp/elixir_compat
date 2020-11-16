require 'test_helper'

class ElixirCompat::PlugCryptoTest < Minitest::Test
  def test_masks_tokens
    assert ElixirCompat::PlugCrypto.mask(0b0101, 0b0110) == 0b0011
    assert ElixirCompat::PlugCrypto.mask(0b0011, 0b0110) == 0b0101
  end

  def test_compares_binaries_securly
    assert ElixirCompat::PlugCrypto.secure_compare("a", "a")
    assert ElixirCompat::PlugCrypto.secure_compare("1", "1")
    assert ElixirCompat::PlugCrypto.secure_compare("69", "69")
    refute ElixirCompat::PlugCrypto.secure_compare("0", "1")
    refute ElixirCompat::PlugCrypto.secure_compare("1", "0")
    refute ElixirCompat::PlugCrypto.secure_compare("0", "1111111")
  end

end
