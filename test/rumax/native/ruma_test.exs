defmodule Rumax.Native.RumaTest do
  use ExUnit.Case
  doctest Rumax.Native.Ruma

  test "greets the world" do
    assert Rumax.Native.Ruma.hello() == :world
  end
end
