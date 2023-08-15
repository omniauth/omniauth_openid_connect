# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/tara/version'

Gem::Specification.new do |spec|
  spec.required_ruby_version = '>= 2.7'
  spec.name          = 'omniauth-tara'
  spec.version       = OmniAuth::Tara::VERSION
  spec.authors       = ['John Bohn', 'Ilya Shcherbinin', 'Artur Beljajev', 'Maciej Szlosarczyk',
    'Sergei Tsõganov']
  spec.email         = ['jjbohn@gmail.com', 'm0n9oose@gmail.com', 'artur.beljajev@internet.ee', 'maciej.szlosarczyk@eestiinternet.ee',
    'sergei.tsoganov@internet.ee']
  spec.summary       = 'TARA-Doku (https://github.com/e-gov/TARA-Doku) strategy for OmniAuth'
  spec.description   = 'TARA-Doku (https://github.com/e-gov/TARA-Doku) strategy for OmniAuth'
  spec.homepage      = 'https://github.com/internetee/omniauth-tara'
  spec.license       = 'MIT/X11'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'omniauth', '>= 1.9', '< 3'
  spec.add_dependency 'openid_connect', '~> 2.2'
  spec.add_development_dependency 'faker', '~> 2.0'
  spec.add_development_dependency 'guard', '~> 2.14'
  spec.add_development_dependency 'guard-bundler', '~> 2.2'
  spec.add_development_dependency 'guard-minitest', '~> 2.4'
  spec.add_development_dependency 'minitest', '~> 5.1'
  spec.add_development_dependency 'mocha', '~> 1.7'
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'rubocop', '~> 1.12'
  spec.add_development_dependency 'simplecov', '~> 0.21'
  spec.add_development_dependency 'simplecov-lcov', '~> 0.8'
  spec.add_development_dependency 'webmock', '~> 3.18'
end
