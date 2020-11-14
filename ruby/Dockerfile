FROM ruby:2.7

RUN mkdir /ruby
WORKDIR /ruby

COPY Gemfile Gemfile.lock elixir_compat.gemspec ./
RUN bundle install
