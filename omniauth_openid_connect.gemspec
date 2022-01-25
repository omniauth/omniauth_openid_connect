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

  spec.metadata = {
    'bug_tracker_uri' => 'https://github.com/m0n9oose/omniauth_openid_connect/issues',
    'changelog_uri' => 'https://github.com/m0n9oose/omniauth_openid_connect/releases',
    'documentation_uri' => "https://github.com/m0n9oose/omniauth_openid_connect/tree/v#{spec.version}#readme",
    'source_code_uri' => "https://github.com/m0n9oose/omniauth_openid_connect/tree/v#{spec.version}",
    'rubygems_mfa_required' => 'true',
  }

  spec.add_dependency 'addressable'
  spec.add_dependency 'omniauth'
  spec.add_dependency 'openid_connect'
  spec.add_dependency 'omniauth-rails_csrf_protection'
  spec.add_development_dependency 'coveralls'
  spec.add_development_dependency 'faker'
  spec.add_development_dependency 'guard'
  spec.add_development_dependency 'guard-bundler'
  spec.add_development_dependency 'guard-minitest'
  spec.add_development_dependency 'minitest'
  spec.add_development_dependency 'mocha'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'simplecov'
end
