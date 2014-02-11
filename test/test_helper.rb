require 'minitest/autorun'
require_relative '../lib/omniauth-openid-connect'

class StrategyTestCase < MiniTest::Test
  def setup
    @identifier = "1234"
    @secret = "1234asdgat3"
  end

  def strategy
    @strategy ||= OmniAuth::Strategies::OpenIDConnect.new(nil).tap do |strategy|
      strategy.options.client_options.identifier = "1234"
      strategy.options.client_options.strategy = "13sdfC41"
    end
  end
end
