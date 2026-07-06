defmodule Rumax.MixProject do
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
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:rustler, "~> 0.38.0", runtime: false},
      {:jason, "~> 1.4"},
      {:jose, "~> 1.11"}
    ]
  end
end
