# OmniAuth::Tara

Originally based on [omniauth_openid_connect](https://github.com/omniauth/omniauth_openid_connect),
with parts rewritten to fit TARA-Doku protocol.

I've forked this repository and launch as separate gem because maintaining of original was dropped.

[![Build Status](https://travis-ci.org/internetee/omniauth-tara.svg?branch=master)](https://travis-ci.org/internetee/omniauth-tara)

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth-tara'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-tara

## Supported Ruby Versions

OmniAuth::Tara is tested under 2.7, 3.0, 3.1, 3.2

## Usage

Example configuration

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :tara, {
    name: :my_provider,
    scope: [:openid, :idcard, :mid, :smartid],
    response_type: :code,
    uid_field: "preferred_username",
    client_options: {
      port: 443,
      scheme: "https",
      host: "myprovider.com",
      identifier: ENV["OP_CLIENT_ID"],
      secret: ENV["OP_SECRET_KEY"],
      redirect_uri: "http://myapp.com/users/auth/openid_connect/callback",
    },
  }
end
```

### Additional Configuration Notes
  * `name` is arbitrary, I recommend using the name of your provider. The name
  configuration exists because you could be using multiple OpenID Connect
  providers in a single app.
  * `response_type` tells the authorization server which grant type the application wants to use,
  currently, only `:code` (Authorization Code grant) is valid.
  * If you want to pass `state` parameter by yourself. You can set Proc Object.
  e.g. `state: Proc.new { SecureRandom.hex(32) }`
  * `nonce` is optional. If don't want to pass "nonce" parameter to provider, You should specify
  `false` to `send_nonce` option. (default true)
  * Support for other client authentication methods. If don't specified
  `:client_auth_method` option, automatically set `:basic`.
  * Use "OpenID Connect Discovery", You should specify `true` to `discovery` option. (default false)
  * In "OpenID Connect Discovery", generally provider should have Webfinger endpoint.
  If provider does not have Webfinger endpoint, You can specify "Issuer" to option.
  e.g. `issuer: "https://myprovider.com"`
  It means to get configuration from "https://myprovider.com/.well-known/openid-configuration".
  * The uid is by default using the `sub` value from the `user_info` response,
  which in some applications is not the expected value. To avoid such limitations, the uid label can be
  configured by providing the omniauth `uid_field` option to a different label (i.e. `preferred_username`)
  that appears in the `user_info` details.
  * The `issuer` property should exactly match the provider's issuer link.
  * The `response_mode` option is optional and specifies how the result of the authorization request is formatted.

For the full low down on OpenID Connect, please check out
[the spec](http://openid.net/specs/openid-connect-core-1_0.html).
