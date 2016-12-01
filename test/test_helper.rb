require 'simplecov'
require 'coveralls'
require 'minitest/autorun'
require 'mocha/mini_test'
require 'faker'
require 'active_support'
require 'omniauth_openid_connect'
require_relative 'strategy_test_case'

SimpleCov.command_name 'test'
SimpleCov.start
Coveralls.wear!
OmniAuth.config.test_mode = true
