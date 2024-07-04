# Unreleased

# v0.8.0 (2024-07-04)

- Add `send_state` parameter to disable sending of state (https://github.com/omniauth/omniauth_openid_connect/pull/182)

# v0.7.1 (2023-04-26)

- Fix handling of JWKS response (https://github.com/omniauth/omniauth_openid_connect/pull/157)

# v0.7.0 (2023-04-25)

- Update openid_connect to 2.2 (https://github.com/omniauth/omniauth_openid_connect/pull/153)
- Drop Ruby 2.5 and 2.6 CI support (https://github.com/omniauth/omniauth_openid_connect/pull/154)
- Improvements to README (https://github.com/omniauth/omniauth_openid_connect/pull/152, https://github.com/omniauth/omniauth_openid_connect/pull/151)
- Add option `logout_path` (https://github.com/omniauth/omniauth_openid_connect/pull/143)

# v0.6.1 (2023-02-22)

- Fix uninitialized constant error (https://github.com/omniauth/omniauth_openid_connect/pull/147)

# v0.6.0 (2023-01-22)

- Support verification of HS256-signed JWTs (https://github.com/omniauth/omniauth_openid_connect/pull/134)

# v0.5.0 (2022-12-26)

- Support the "nonce" parameter forwarding without a session [#130](https://github.com/omniauth/omniauth_openid_connect/pull/130)
- Fetch key from JWKS URI if available [#133](https://github.com/omniauth/omniauth_openid_connect/pull/133)
- Make the state parameter verification optional [#122](https://github.com/omniauth/omniauth_openid_connect/pull/122)
- Add email_verified claim in user info [#131](https://github.com/omniauth/omniauth_openid_connect/pull/131)
- Add PKCE verification support [#128](https://github.com/omniauth/omniauth_openid_connect/pull/128)

# v0.4.0 (2022-02-06)

- Support dynamic parameters to the authorize URI [#90](https://github.com/omniauth/omniauth_openid_connect/pull/90)
- Upgrade Faker and replace Travis with Github Actions [#102](https://github.com/omniauth/omniauth_openid_connect/pull/102)
- Make `omniauth_openid_connect` gem compatible with `omniauth v2.0` [#95](https://github.com/omniauth/omniauth_openid_connect/pull/95)
- Fall back to the discovered jwks when no key specified [#97](https://github.com/omniauth/omniauth_openid_connect/pull/97)
- Allow updating to omniauth v2 [#88](https://github.com/omniauth/omniauth_openid_connect/pull/88)

# v0.3.5 (2020-06-07)

- bugfix: Info from decoded id_token is not exposed into `request.env['omniauth.auth']` [#61](https://github.com/m0n9oose/omniauth_openid_connect/pull/61)
- bugfix: NoMethodError (`undefined method 'count' for #<OpenIDConnect::ResponseObject::IdToken>`) [#60](https://github.com/m0n9oose/omniauth_openid_connect/pull/60)

# v0.3.4 (2020-05-21)

- Try to verify id_token when response_type is code [#44](https://github.com/m0n9oose/omniauth_openid_connect/pull/44)
- Provide more information on error [#49](https://github.com/m0n9oose/omniauth_openid_connect/pull/49)
- Update configuration documentation [#53](https://github.com/m0n9oose/omniauth_openid_connect/pull/53)
- Add documentation about the send_scope_to_token_endpoint config property [#52](https://github.com/m0n9oose/omniauth_openid_connect/pull/52)
- refactor: take uid_field from raw_attributes [#54](https://github.com/m0n9oose/omniauth_openid_connect/pull/54)
- chore(ci): add 2.7, ruby-head and jruby-head [#55](https://github.com/m0n9oose/omniauth_openid_connect/pull/55)

# v0.3.3 (2019-11-09)

- Pass `acr_values` to authorize url [#43](https://github.com/m0n9oose/omniauth_openid_connect/pull/43)
- Add raw info for id token [#42](https://github.com/m0n9oose/omniauth_openid_connect/pull/42)
- Fixed `id_token` verification when `id_token` is not used [#41](https://github.com/m0n9oose/omniauth_openid_connect/pull/41)
- Cast `response_type` to string when checking if it is set in params [#36](https://github.com/m0n9oose/omniauth_openid_connect/pull/36)
- Support both symbol and string version of `response_type` option [#35](https://github.com/m0n9oose/omniauth_openid_connect/pull/35)
- Fix gemspec homepage [#33](https://github.com/m0n9oose/omniauth_openid_connect/pull/33)
- Add support for `response_type` `id_token` [#32](https://github.com/m0n9oose/omniauth_openid_connect/pull/32)

# v0.3.2 (2019-08-03)

- Use response_mode in `authorize_uri` if the option is defined [#30](https://github.com/m0n9oose/omniauth_openid_connect/pull/30)
- Move verification of `id_token` to before accessing tokens [#28](https://github.com/m0n9oose/omniauth_openid_connect/pull/28)
- Update omniauth dependency [#26](https://github.com/m0n9oose/omniauth_openid_connect/pull/26)

# v0.3.1 (2019-06-08)

- Set default OmniAuth name to openid_connect [#23](https://github.com/m0n9oose/omniauth_openid_connect/pull/23)

# v0.3.0 (2019-04-07)

- RP-Initiated Logout phase [#5](https://github.com/m0n9oose/omniauth_openid_connect/pull/5)
- Allows `ui_locales`, `claims_locales` and `login_hint` as request params [#6](https://github.com/m0n9oose/omniauth_openid_connect/pull/6)
- Make uid label configurable [#11](https://github.com/m0n9oose/omniauth_openid_connect/pull/11)
- Allow rails applications to handle state mismatch [#14](https://github.com/m0n9oose/omniauth_openid_connect/pull/14)
- Handle errors when fetching access_token at callback_phase [#17](https://github.com/m0n9oose/omniauth_openid_connect/pull/17)
- Allow state method to receive env [#19](https://github.com/m0n9oose/omniauth_openid_connect/pull/19)

# v0.2.4 (2019-01-06)

- Prompt and login hint [#4](https://github.com/m0n9oose/omniauth_openid_connect/pull/4)
- Bump openid_connect dependency [#9](https://github.com/m0n9oose/omniauth_openid_connect/pull/9)
