FROM elixir:1.11

RUN mkdir /elixir
WORKDIR /elixir

COPY mix.exs mix.lock ./
RUN mix local.hex --force && mix local.rebar --force && mix deps.get
