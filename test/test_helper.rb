# -*- coding:utf-8 -*-
# frozen_string_literal: true

lib = File.expand_path('../lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'simplecov'
require 'minitest/autorun'
require 'mocha/minitest'
require 'faker'
require 'omniauth'

SimpleCov.start do
  if ENV['CI']
    require 'simplecov-lcov'

    SimpleCov::Formatter::LcovFormatter.config do |c|
      c.report_with_single_file = true
      c.single_report_path = 'coverage/lcov.info'
    end

    formatter SimpleCov::Formatter::LcovFormatter
  end
end

require 'omniauth_openid_connect'
require_relative 'strategy_test_case'

OmniAuth.config.test_mode = true
