# OmniAuth::OpenIDConnect

Fork of [omniauth-openid-connect](https://github.com/omniauth/omniauth_openid_connect)

[![Build Status](https://github.com/omniauth/omniauth_openid_connect/actions/workflows/main.yml/badge.svg)](https://github.com/omniauth/omniauth_openid_connect/actions/workflows/main.yml)
[![Coverage Status](https://coveralls.io/repos/github/omniauth/omniauth_openid_connect/badge.svg)](https://coveralls.io/github/omniauth/omniauth_openid_connect)

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth_openid_connect', git "https://github.com/wakeoTeam/omniauth_openid_connect"

And then execute:

    $ bundle

## Supported Ruby Versions

OmniAuth::OpenIDConnect is tested under 2.5, 2.6, 2.7, 3.0, 3.1

## Usage

Example configuration

In `config/initializers/omniauth.rb` file

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
    configure do |config|
        config.path_prefix = ::Constants::REDIRECT_OIDC_PATH
    end

    provider :openid_connect,{
    #name: somaudex,
    name: :openid_connect,
    scope: [:openid, :email],
    response_type: :code,
    issuer: "https://#{ENV["OIDC_HOST"]}",
    uid_field: "sub",
    send_nonce: false,
    client_options: {
      port: 443,
      scheme: "https",
      host: ENV["OIDC_HOST"],
      identifier: "wakeo",
      secret: ENV["OIDC_SECRET_KEY"],
      authorization_endpoint: "/OpenID/Authorize",
      token_endpoint: "/OpenID/AccessToken",
      jwks_uri: "https://#{ENV["OIDC_HOST"]}/OpenID/Discovery/jwks.json",
      redirect_uri: "http://{APP_HOST}/#{::Constants::REDIRECT_OIDC_PATH}/callback",
    }}
  end
```

### Options Overview

| Field                        | Description                                                                                                                                                   | Required | Default                       | Example/Options                                     |
|------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|-------------------------------|-----------------------------------------------------|
| name                         | Arbitrary string to identify connection and identify it from other openid_connect providers                                                                   | no       | String: openid_connect        | :my_idp                                             |
| issuer                       | Root url for the authorization server                                                                                                                         | yes      |                               | https://myprovider.com                              |
| client_auth_method           | Which authentication method to use to authenticate your app with the authorization server                                                                     | no       | Sym: basic                    | "basic", "jwks"                                     |
| scope                        | Which OpenID scopes to include (:openid is always required)                                                                                                   | no       | Array<sym> [:openid]          | [:openid, :profile, :email]                         |
| response_type                | Which OAuth2 response type to use with the authorization request                                                                                              | no       | String: code                  | one of: 'code', 'id_token'                          |
| state                        | A value to be used for the OAuth2 state parameter on the authorization request. Can be a proc that generates a string.                                        | no       | Random 16 character string    | Proc.new { SecureRandom.hex(32) }                   |
| response_mode                | The response mode per [spec](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                                              | no       | nil                           | one of: :query, :fragment, :form_post, :web_message |
| display                      | An optional parameter to the authorization request to determine how the authorization and consent page                                                        | no       | nil                           | one of: :page, :popup, :touch, :wap                 |
| prompt                       | An optional parameter to the authrization request to determine what pages the user will be shown                                                              | no       | nil                           | one of: :none, :login, :consent, :select_account    |
| send_scope_to_token_endpoint | Should the scope parameter be sent to the authorization token endpoint?                                                                                       | no       | true                          | one of: true, false                                 |
| post_logout_redirect_uri     | The logout redirect uri to use per the [session management draft](https://openid.net/specs/openid-connect-session-1_0.html)                                   | no       | empty                         | https://myapp.com/logout/callback                   |
| uid_field                    | The field of the user info response to be used as a unique id                                                                                                 | no       | 'sub'                         | "sub", "preferred_username"                         |
| extra_authorize_params       | A hash of extra fixed parameters that will be merged to the authorization request                                                                             | no       | Hash                          | {"tenant" => "common"}                              |
| allow_authorize_params       | A list of allowed dynamic parameters that will be merged to the authorization request                                                                         | no       | Array                         | [:screen_name]                                      |
| pkce                         | Enable [PKCE flow](https://oauth.net/2/pkce/)                                                                                                                 | no       | false                         | one of: true, false                                 |
| pkce_verifier                | Specify a custom PKCE verifier code.                                                                                                                          | no       | A random 128-char string      | Proc.new { SecureRandom.hex(64) }                   |
| pkce_options                 | Specify a custom implementation of the PKCE code challenge/method.                                                                                            | no       | SHA256(code_challenge) in hex | Proc to customise the code challenge generation     |
| client_options               | A hash of client options detailed in its own section                                                                                                          | yes      |                               |                                                     |

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

### Additional notes
  * In some cases, you may want to go straight to the callback phase - e.g. when requested by a stateless client, like a mobile app.
  In such example, the session is empty, so you have to forward certain parameters received from the client.
  Currently supported one is `code_verifier` - simply provide it as the `/callback` request parameter.

For the full low down on OpenID Connect, please check out
[the spec](http://openid.net/specs/openid-connect-core-1_0.html).
