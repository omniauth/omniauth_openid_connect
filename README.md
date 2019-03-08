# OmniAuth::OpenIDConnect

Originally was [omniauth-openid-connect](https://github.com/jjbohn/omniauth-openid-connect)

I've forked this repository and launch as separate gem because maintaining of original was dropped.

[![Build Status](https://travis-ci.org/m0n9oose/omniauth_openid_connect.png?branch=master)](https://travis-ci.org/m0n9oose/omniauth_openid_connect)

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth_openid_connect'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth_openid_connect

## Usage

Example configuration
```ruby
config.omniauth :openid_connect, {
  name: :my_provider,
  scope: [:openid, :email, :profile, :address],
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
```

Configuration details:
  * `name` is arbitrary, I recommend using the name of your provider. The name
  configuration exists because you could be using multiple OpenID Connect
  providers in a single app.

  **NOTE**: if you use this gem with Devise you should use `:openid_connect` name,
  or Devise would route to 'users/auth/:provider' rather than 'users/auth/openid_connect'

  * Although `response_type` is an available option, currently, only `:code`
  is valid. There are plans to bring in implicit flow and hybrid flow at some
  point, but it hasn't come up yet for me. Those flows aren't best practive for
  server side web apps anyway and are designed more for native/mobile apps.
  * If you want to pass `state` paramete by yourself. You can set Proc Object.
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

For the full low down on OpenID Connect, please check out
[the spec](http://openid.net/specs/openid-connect-core-1_0.html).

## Contributing

1. Fork it ( http://github.com/m0n9oose/omniauth-openid-connect/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Cover your changes with tests and make sure they're green (`bundle install && bundle exec rake test`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin my-new-feature`)
6. Create new Pull Request
