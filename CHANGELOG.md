# v0.4.0 (5.06.2019)

- Add claims parameter to authorize request
- Allow options to be modified both by options and by request parameters, prioritizing request parameters
- Support back to Ruby 2.3
- Make it clear what options come from what standards

# v0.3.1 (08.06.2019)

- Set default OmniAuth name to openid_connect [#23](https://github.com/m0n9oose/omniauth_openid_connect/pull/23)

# v0.3.0 (27.04.2019)

- RP-Initiated Logout phase [#5](https://github.com/m0n9oose/omniauth_openid_connect/pull/5)
- Allows `ui_locales`, `claims_locales` and `login_hint` as request params [#6](https://github.com/m0n9oose/omniauth_openid_connect/pull/6)
- Make uid label configurable [#11](https://github.com/m0n9oose/omniauth_openid_connect/pull/11)
- Allow rails applications to handle state mismatch [#14](https://github.com/m0n9oose/omniauth_openid_connect/pull/14)
- Handle errors when fetching access_token at callback_phase [#17](https://github.com/m0n9oose/omniauth_openid_connect/pull/17)
- Allow state method to receive env [#19](https://github.com/m0n9oose/omniauth_openid_connect/pull/19)

# v0.2.4 (06.01.2019)

- Prompt and login hint [#4](https://github.com/m0n9oose/omniauth_openid_connect/pull/4)
- Bump openid_connect dependency [#9](https://github.com/m0n9oose/omniauth_openid_connect/pull/9)
