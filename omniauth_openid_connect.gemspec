# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/openid_connect/version'

Gem::Specification.new do |spec|
  spec.add_dependency 'addressable', '~> 2.5'
  spec.add_dependency 'omniauth', '~> 1.3'
  spec.add_dependency 'openid_connect', '~> 1.1'
  spec.add_development_dependency 'coveralls', '~> 0.8'
  spec.add_development_dependency 'faker', '~> 1.6'
  spec.add_development_dependency 'guard', '~> 2.14'
  spec.add_development_dependency 'guard-bundler', '~> 2.2'
  spec.add_development_dependency 'guard-minitest', '~> 2.4'
  spec.add_development_dependency 'minitest', '~> 5.1'
  spec.add_development_dependency 'mocha', '~> 1.7'
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'rubocop', '~> 0.63'
  spec.add_development_dependency 'simplecov', '~> 0.12'
  spec.authors       = ['John Bohn', 'Ilya Shcherbinin']
  spec.description   = 'OpenID Connect Strategy for OmniAuth.'
  spec.email         = ['jjbohn@gmail.com', 'm0n9oose@gmail.com']
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.files         = `git ls-files -z`.split("\x0")
  spec.homepage      = 'https://github.com/m0n9oose/omniauth_openid_connect'
  spec.license       = 'MIT'
  spec.name          = 'omniauth_openid_connect'
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 2.3'
  spec.summary       = spec.description
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.version       = OmniAuth::OpenIDConnect::VERSION
end
