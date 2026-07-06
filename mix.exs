defmodule Rumax.Native.Ruma.MixProject do
  use Mix.Project

  def project do
    [
      app: :rumax,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Rumax.Native.Ruma.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.38.0", runtime: false}
    ]
  end
end
