require 'test_helper'

class ElixirCompat::PlugCrypto::KeyGeneratorTest < Minitest::Test
  def generate(*args)
    ElixirCompat::PlugCrypto::KeyGenerator.generate(*args)
  end

  def test_errors_when_iterations_is_a_string
    assert_raises ArgumentError do
      generate("secret", "salt", iterations: "many")
    end
  end

  def test_errors_when_iterations_is_a_atom
    assert_raises ArgumentError do
      generate("secret", "salt", iterations: :lots)
    end
  end

  def test_errors_when_iterations_is_a_float
    assert_raises ArgumentError do
      generate("secret", "salt", iterations: 3.1415)
    end
  end

  def test_errors_when_iterations_is_not_an_integer
    assert_raises ArgumentError do
      generate("secret", "salt", iterations: "17")
    end
  end

  def test_errors_when_iterations_is_zero
    assert_raises ArgumentError do
      generate("secret", "salt", iterations: 0)
    end
  end

  def test_errors_when_length_is_a_string
    assert_raises ArgumentError do
      generate("secret", "salt", length: "many")
    end
  end

  def test_errors_when_length_is_a_atom
    assert_raises ArgumentError do
      generate("secret", "salt", length: :lots)
    end
  end

  def test_errors_when_length_is_zero
    assert_raises ArgumentError do
      generate("secret", "salt", length: 0)
    end
  end

  def test_errors_when_length_is_greater_than_max
    max = (1 << 32) - 1
    assert_raises ArgumentError do
      generate("secret", "salt", length: max + 1)
    end
  end

  def test_errors_when_unknown_digest
    assert_raises ArgumentError do
      generate("secret", "salt", digest: :new_digest_type)
    end
  end

  def test_can_generate_sha_key_with_1_iteration
    key = generate("password", "salt", iterations: 1, length: 20, digest: :sha1)
    assert key.bytesize == 20
    assert to_hex(key) == "0c60c80f961f0e71f3a9b524af6012062fe037a6"
  end

  def test_can_generate_sha_key_with_2_iterations
    key = generate("password", "salt", iterations: 2, length: 20, digest: :sha1)
    assert key.bytesize == 20
    assert to_hex(key) == "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
  end

  def test_can_generate_sha_key_with_4096_iterations
    key = generate("password", "salt", iterations: 4096, length: 20, digest: :sha1)
    assert key.bytesize == 20
    assert to_hex(key) == "4b007901b765489abead49d926f721d065a429c1"
  end

  def test_can_generate_with_longer_secrets
    key = generate("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", iterations: 4096, length: 25, digest: :sha1)

    assert key.bytesize == 25
    assert to_hex(key) == "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
  end

  def test_can_generate_with_null_characters
    key = generate("pass\0word", "sa\0lt", iterations: 4096, length: 16, digest: :sha1)
    assert key.bytesize == 16
    assert to_hex(key) == "56fa6aa75548099dcc37d7f03425e0c3"
  end

  def test_can_generate_with_default_options
    key = generate("password", "salt")
    assert key.bytesize == 32
    assert to_hex(key) == "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"
  end

  def test_can_generate_with_digest_option
    key = generate("password", "salt", digest: :sha1)
    assert key.bytesize == 32
    assert to_hex(key) == "6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214"
  end

  def test_can_generate_with_length_option
    key = generate("password", "salt", length: 64, digest: :sha1)
    assert key.bytesize == 64
    assert to_hex(key) == "6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214ce970d912ec2049b04231d47c2eb88506945b26b2325e6adfeeba08895ff9587"
  end

  def to_hex(bin)
    bin.unpack('H*').first
  end

end
