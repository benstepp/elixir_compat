FROM elixir:1.11

RUN mix local.hex --force && mix local.rebar --force

RUN mkdir /elixir
WORKDIR /elixir

COPY mix.exs mix.lock ./
RUN mix deps.get
RUN mix deps.compile
