# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/openid_connect/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth_openid_connect'
  spec.version       = OmniAuth::OpenIDConnect::VERSION
  spec.authors       = ['John Bohn', 'Ilya Shcherbinin']
  spec.email         = ['jjbohn@gmail.com', 'm0n9oose@gmail.com']
  spec.summary       = 'OpenID Connect Strategy for OmniAuth'
  spec.description   = 'OpenID Connect Strategy for OmniAuth.'
  spec.homepage      = 'https://github.com/m0n9oose/omniauth_openid_connect'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'addressable', '~> 2.7'
  spec.add_dependency 'omniauth', '~> 1.9'
  spec.add_dependency 'openid_connect', '~> 1.2'
  spec.add_development_dependency 'coveralls', '~> 0.8'
  spec.add_development_dependency 'faker', '~> 2.17'
  spec.add_development_dependency 'guard', '~> 2.14'
  spec.add_development_dependency 'guard-bundler', '~> 3.0'
  spec.add_development_dependency 'guard-minitest', '~> 2.4'
  spec.add_development_dependency 'minitest', '~> 5.14'
  spec.add_development_dependency 'mocha', '~> 1.12'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rubocop', '~> 1.12'
  spec.add_development_dependency 'simplecov', '~> 0.16'
end
