defmodule ElixirCompat.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixir_compat,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.2.2"},
      {:phoenix, "~> 1.5"},
      {:plug_crypto, "~> 1.0"},
      {:uuid, "~> 1.1.8"}
    ]
  end
end
