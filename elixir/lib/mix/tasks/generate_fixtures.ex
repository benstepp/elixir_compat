defmodule Mix.Tasks.GenerateFixtures do
  use Mix.Task

  @shortdoc "Generates cross language fixtures"
  def run(_) do
    Mix.Task.run("app.start")
    ElixirCompat.Generator.run()
  end
end
