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
    
## Supported Ruby Versions

OmniAuth::OpenIDConnect is tested under 2.4, 2.5, 2.6, 2.7

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

### Options Overview

| Field                        | Description                                                                                                                                                   | Required | Default                    | Example/Options                                     |
|------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|----------------------------|-----------------------------------------------------|
| name                         | Arbitrary string to identify connection and identify it from other openid_connect providers                                                                   | no       | String: openid_connect     | :my_idp                                             |
| issuer                       | Root url for the authorization server                                                                                                                         | yes      |                            | https://myprovider.com                              |
| discovery                    | Should OpenID discovery be used. This is recommended if the IDP provides a discovery endpoint. See client config for how to manually enter discovered values. | no       | false                      | one of: true, false                                 |
| client_auth_method           | Which authentication method to use to authenticate your app with the authorization server                                                                     | no       | Sym: basic                 | "basic", "jwks"                                     |
| scope                        | Which OpenID scopes to include (:openid is always required)                                                                                                   | no       | Array<sym> [:openid]       | [:openid, :profile, :email]                         |
| response_type                | Which OAuth2 response type to use with the authorization request                                                                                              | no       | String: code               | one of: 'code', 'id_token'                          |
| state                        | A value to be used for the OAuth2 state parameter on the authorization request. Can be a proc that generates a string.                                        | no       | Random 16 character string | Proc.new { SecureRandom.hex(32) }                   |
| response_mode                | The response mode per [spec](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                                              | no       | nil                        | one of: :query, :fragment, :form_post, :web_message |
| display                      | An optional parameter to the authorization request to determine how the authorization and consent page                                                        | no       | nil                        | one of: :page, :popup, :touch, :wap                 |
| prompt                       | An optional parameter to the authrization request to determine what pages the user will be shown                                                              | no       | nil                        | one of: :none, :login, :consent, :select_account    |
| send_scope_to_token_endpoint | Should the scope parameter be sent to the authorization token endpoint?                                                                                       | no       | true                       | one of: true, false                                 |
| post_logout_redirect_uri     | The logout redirect uri to use per the [session management draft](https://openid.net/specs/openid-connect-session-1_0.html)                                   | no       | empty                      | https://myapp.com/logout/callback                   |
| uid_field                    | The field of the user info response to be used as a unique id                                                                                                 | no       | 'sub'                      | "sub", "preferred_username"                         |
| pkce                         | Enable [PKCE flow](https://oauth.net/2/pkce/)                                                                                                                 | no       | false                      | one of: true, false                                 |
| pkce_verifier                | Specify a custom PKCE verifier code.                                                                                                                          | no       | Random 32 character string | Proc.new { SecureRandom.hex(64) }                   |
| pkce_options                 | Specify a custom implementation of the PKCE code challenge/method.                                                                                            | no       | Hash with default impl     | Proc to customise the code challenge generation     |
| client_options               | A hash of client options detailed in its own section                                                                                                          | yes      |                            |                                                     |

### Client Config Options

These are the configuration options for the client_options hash of the configuration.

| Field                  | Description                                                     | Default    | Replaced by discovery? |
|------------------------|-----------------------------------------------------------------|------------|------------------------|
| identifier             | The OAuth2 client_id                                            |            |                        |
| secret                 | The OAuth2 client secret                                        |            |                        |
| redirect_uri           | The OAuth2 authorization callback url in your app               |            |                        |
| scheme                 | The http scheme to use                                          | https      |                        |
| host                   | The host of the authorization server                            | nil        |                        |
| port                   | The port for the authorization server                           | 443        |                        |
| authorization_endpoint | The authorize endpoint on the authorization server              | /authorize | yes                    |
| token_endpoint         | The token endpoint on the authorization server                  | /token     | yes                    |
| userinfo_endpoint      | The user info endpoint on the authorization server              | /userinfo  | yes                    |
| jwks_uri               | The jwks_uri on the authorization server                        | /jwk       | yes                    |
| end_session_endpoint   | The url to call to log the user out at the authorization server | nil        | yes                    |

### Additional Configuration Notes
  * `name` is arbitrary, I recommend using the name of your provider. The name
  configuration exists because you could be using multiple OpenID Connect
  providers in a single app.

  **NOTE**: if you use this gem with Devise you should use `:openid_connect` name,
  or Devise would route to 'users/auth/:provider' rather than 'users/auth/openid_connect'

  * `response_type` tells the authorization server which grant type the application wants to use,
  currently, only `:code` (Authorization Code grant) and `:id_token` (Implicit grant) are valid.
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
  * Some OpenID Connect providers require the `scope` attribute in requests to the token endpoint, even if
  this is not in the protocol specifications. In those cases, the `send_scope_to_token_endpoint`
  property can be used to add the attribute to the token request. Initial value is `true`, which means that the
  scope attribute is included by default.
  * PKCE flow is supported, simple set the PKCE option to true. Use the PKCE verifier and/or PKCE options settings to customise.

For the full low down on OpenID Connect, please check out
[the spec](http://openid.net/specs/openid-connect-core-1_0.html).

## Contributing

1. Fork it ( http://github.com/m0n9oose/omniauth-openid-connect/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Cover your changes with tests and make sure they're green (`bundle install && bundle exec rake test`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin my-new-feature`)
6. Create new Pull Request
