defmodule ElixirCompatTest do
  use ExUnit.Case
  doctest ElixirCompat

  test "greets the world" do
    assert ElixirCompat.hello() == :world
  end
end
