lib = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'simplecov'
require 'coveralls'
require 'minitest/autorun'
require 'mocha/minitest'
require 'faker'
require 'active_support'
require 'omniauth_openid_connect'
require_relative 'strategy_test_case'

SimpleCov.command_name 'test'
SimpleCov.start
Coveralls.wear!
OmniAuth.config.test_mode = true
