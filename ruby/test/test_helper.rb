$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "elixir_compat"

require "minitest/autorun"

class ElixirCompat::Fixtures
  class << self
    def load(fixture_name)
      require 'json'
      JSON.parse(File.read("fixtures/#{fixture_name}.json"), symbolize_names: true)
    end
  end
end
