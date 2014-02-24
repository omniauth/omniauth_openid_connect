require 'simplecov'
SimpleCov.command_name 'test'
SimpleCov.start

require 'coveralls'
Coveralls.wear!

require 'minitest/autorun'
require 'mocha/mini_test'
require 'faker'
require_relative '../lib/omniauth-openid-connect'

OmniAuth.config.test_mode = true

class StrategyTestCase < MiniTest::Test
  class DummyApp
    def call(env); end
  end

  attr_accessor :identifier, :secret

  def setup
    @identifier = "1234"
    @secret = "1234asdgat3"
  end

  def client
    strategy.client
  end

  def user_info
    @user_info ||= stub('OpenIDConnect::ResponseObject::UserInfo').tap do |info|
      info.stubs(:sub).returns(SecureRandom.hex(16))
      info.stubs(:name).returns(Faker::Name.name)
      info.stubs(:email).returns(Faker::Internet.email)
    end
  end

  def request
    @request ||= stub('Request').tap do |request|
      request.stubs(:params).returns({})
      request.stubs(:cookies).returns({})
      request.stubs(:env).returns({})
      request.stubs(:scheme).returns({})
      request.stubs(:ssl?).returns(false)
    end
  end

  def strategy
    @strategy ||= OmniAuth::Strategies::OpenIDConnect.new(DummyApp.new).tap do |strategy|
      strategy.options.client_options.identifier = @identifier
      strategy.options.client_options.secret = @secret
      strategy.stubs(:request).returns(request)
    end
  end
end
