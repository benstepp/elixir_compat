defmodule ElixirCompat.Generator do
  @moduledoc """
  Generates all the fixtures
  """

  alias __MODULE__

  def run() do
    Generator.PlugCrypto.run()
  end
end
