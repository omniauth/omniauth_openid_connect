# frozen_string_literal: true

require_relative '../../../test_helper'

module OmniAuth
  module Strategies
    class OpenIDConnectTest < StrategyTestCase # rubocop:disable Metrics/ClassLength
      def test_client_options_defaults
        assert_equal 'https', strategy.options.client_options.scheme
        assert_equal 443, strategy.options.client_options.port
        assert_equal '/authorize', strategy.options.client_options.authorization_endpoint
        assert_equal '/token', strategy.options.client_options.token_endpoint
      end

      def test_request_phase
        expected_redirect = %r{^https://example\.com/authorize\?client_id=1234&nonce=\w{32}&response_type=code&scope=openid&state=\w{32}$}
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end

      def test_logout_phase_with_discovery
        expected_redirect = %r{^https://example\.com/logout$}
        strategy.options.client_options.host = 'example.com'
        strategy.options.discovery = true

        issuer = stub('OpenIDConnect::Discovery::Issuer')
        issuer.stubs(:issuer).returns('https://example.com/')
        ::OpenIDConnect::Discovery::Provider.stubs(:discover!).returns(issuer)

        config = stub('OpenIDConnect::Discovery::Provder::Config')
        config.stubs(:authorization_endpoint).returns('https://example.com/authorization')
        config.stubs(:token_endpoint).returns('https://example.com/token')
        config.stubs(:userinfo_endpoint).returns('https://example.com/userinfo')
        config.stubs(:jwks_uri).returns('https://example.com/jwks')
        config.stubs(:end_session_endpoint).returns('https://example.com/logout')
        ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

        request.stubs(:path_info).returns('/auth/openid_connect/logout')
        request.stubs(:path).returns('/auth/openid_connect/logout')

        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.other_phase
      end

      def test_logout_phase_with_discovery_and_post_logout_redirect_uri
        expected_redirect = 'https://example.com/logout?post_logout_redirect_uri=https%3A%2F%2Fmysite.com'
        strategy.options.client_options.host = 'example.com'
        strategy.options.discovery = true
        strategy.options.post_logout_redirect_uri = 'https://mysite.com'

        issuer = stub('OpenIDConnect::Discovery::Issuer')
        issuer.stubs(:issuer).returns('https://example.com/')
        ::OpenIDConnect::Discovery::Provider.stubs(:discover!).returns(issuer)

        config = stub('OpenIDConnect::Discovery::Provder::Config')
        config.stubs(:authorization_endpoint).returns('https://example.com/authorization')
        config.stubs(:token_endpoint).returns('https://example.com/token')
        config.stubs(:userinfo_endpoint).returns('https://example.com/userinfo')
        config.stubs(:jwks_uri).returns('https://example.com/jwks')
        config.stubs(:end_session_endpoint).returns('https://example.com/logout')
        ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

        request.stubs(:path_info).returns('/auth/openid_connect/logout')
        request.stubs(:path).returns('/auth/openid_connect/logout')

        strategy.expects(:redirect).with(expected_redirect)
        strategy.other_phase
      end

      def test_logout_phase
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'

        request.stubs(:path).returns('/auth/openid_connect/logout')

        strategy.expects(:call_app!)
        strategy.other_phase
      end

      def test_request_phase_with_params
        expected_redirect = %r{^https://example\.com/authorize\?claims_locales=es&client_id=1234&login_hint=john.doe%40example.com&nonce=\w{32}&response_type=code&scope=openid&state=\w{32}&ui_locales=en$}
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'
        request.stubs(:params).returns('login_hint' => 'john.doe@example.com', 'ui_locales' => 'en', 'claims_locales' => 'es')

        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end

      def test_request_phase_with_discovery
        expected_redirect = %r{^https://example\.com/authorization\?client_id=1234&nonce=\w{32}&response_type=code&scope=openid&state=\w{32}$}
        strategy.options.client_options.host = 'example.com'
        strategy.options.discovery = true

        issuer = stub('OpenIDConnect::Discovery::Issuer')
        issuer.stubs(:issuer).returns('https://example.com/')
        ::OpenIDConnect::Discovery::Provider.stubs(:discover!).returns(issuer)

        config = stub('OpenIDConnect::Discovery::Provder::Config')
        config.stubs(:authorization_endpoint).returns('https://example.com/authorization')
        config.stubs(:token_endpoint).returns('https://example.com/token')
        config.stubs(:userinfo_endpoint).returns('https://example.com/userinfo')
        config.stubs(:jwks_uri).returns('https://example.com/jwks')
        ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase

        assert_equal strategy.options.issuer, 'https://example.com/'
        assert_equal strategy.options.client_options.authorization_endpoint, 'https://example.com/authorization'
        assert_equal strategy.options.client_options.token_endpoint, 'https://example.com/token'
        assert_equal strategy.options.client_options.userinfo_endpoint, 'https://example.com/userinfo'
        assert_equal strategy.options.client_options.jwks_uri, 'https://example.com/jwks'
        assert_nil strategy.options.client_options.end_session_endpoint
      end

      def test_request_phase_with_response_mode
        expected_redirect = %r{^https://example\.com/authorize\?client_id=1234&nonce=\w{32}&response_mode=form_post&response_type=id_token&scope=openid&state=\w{32}$}
        strategy.options.issuer = 'example.com'
        strategy.options.response_mode = 'form_post'
        strategy.options.response_type = 'id_token'
        strategy.options.client_options.host = 'example.com'

        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end

      def test_request_phase_with_response_mode_symbol
        expected_redirect = %r{^https://example\.com/authorize\?client_id=1234&nonce=\w{32}&response_mode=form_post&response_type=id_token&scope=openid&state=\w{32}$}
        strategy.options.issuer = 'example.com'
        strategy.options.response_mode = 'form_post'
        strategy.options.response_type = :id_token
        strategy.options.client_options.host = 'example.com'

        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end

      def test_option_acr_values
        strategy.options.client_options[:host] = 'foobar.com'

        refute_match(/acr_values=/, strategy.authorize_uri, 'URI must not contain acr_values')

        strategy.options.acr_values = 'urn:some:acr:values:value'
        assert_match(/acr_values=/, strategy.authorize_uri, 'URI must contain acr_values')
      end

      def test_option_custom_attributes
        strategy.options.client_options[:host] = 'foobar.com'
        strategy.options.extra_authorize_params = { resource: 'xyz' }

        assert(strategy.authorize_uri =~ /resource=xyz/, 'URI must contain custom params')
      end

      def test_request_phase_with_allowed_params
        strategy.options.issuer = 'example.com'
        strategy.options.allow_authorize_params = %i[name logo resource]
        strategy.options.extra_authorize_params = { resource: 'xyz' }
        strategy.options.client_options.host = 'example.com'
        request.stubs(:params).returns('name' => 'example', 'logo' => 'example_logo', 'resource' => 'abc',
                                       'not_allowed' => 'filter_me')

        assert(strategy.authorize_uri =~ /resource=xyz/, 'URI must contain fixed param resource')
        assert(strategy.authorize_uri =~ /name=example/, 'URI must contain dynamic param name')
        assert(strategy.authorize_uri =~ /logo=example_logo/, 'URI must contain dynamic param logo')
        refute(strategy.authorize_uri =~ /not_allowed=filter_me/, 'URI must filter not allowed param')
      end

      def test_uid
        assert_equal user_info.sub, strategy.uid

        strategy.options.uid_field = 'preferred_username'
        assert_equal user_info.preferred_username, strategy.uid

        strategy.options.uid_field = 'something'
        assert_equal user_info.sub, strategy.uid
      end

      def test_callback_phase(_session = {}, _params = {}) # rubocop:disable Metrics/AbcSize
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = jwks.to_s
        strategy.options.response_type = 'code'

        strategy.unstub(:user_info)
        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token)
        access_token.stubs(:refresh_token)
        access_token.stubs(:expires_in)
        access_token.stubs(:scope)
        access_token.stubs(:id_token).returns(jwt.to_s)
        client.expects(:access_token!).at_least_once.returns(access_token)
        access_token.expects(:userinfo!).returns(user_info)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:raw_attributes).returns('sub' => 'sub', 'name' => 'name', 'email' => 'email')
        id_token.stubs(:verify!).with(issuer: strategy.options.issuer, client_id: @identifier, nonce: nonce).returns(true)
        id_token.expects(:verify!)

        strategy.expects(:decode_id_token).twice.with(access_token.id_token).returns(id_token)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_id_token
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => jwt.to_s, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = jwks.to_json
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token)
        access_token.stubs(:refresh_token)
        access_token.stubs(:expires_in)
        access_token.stubs(:scope)
        access_token.stubs(:id_token).returns(jwt.to_s)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:raw_attributes).returns('sub' => 'sub', 'name' => 'name', 'email' => 'email')
        id_token.stubs(:verify!).with(issuer: strategy.options.issuer, client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)
        id_token.expects(:verify!)

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_id_token_and_param_provided_nonce # rubocop:disable Metrics/AbcSize
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state, 'nonce' => nonce)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = jwks.to_s
        strategy.options.response_type = 'code'

        strategy.unstub(:user_info)
        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token)
        access_token.stubs(:refresh_token)
        access_token.stubs(:expires_in)
        access_token.stubs(:scope)
        access_token.stubs(:id_token).returns(jwt.to_s)
        client.expects(:access_token!).at_least_once.returns(access_token)
        access_token.expects(:userinfo!).returns(user_info)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:raw_attributes).returns('sub' => 'sub', 'name' => 'name', 'email' => 'email')
        id_token.stubs(:verify!).with(issuer: strategy.options.issuer, client_id: @identifier, nonce: nonce).returns(true)
        id_token.expects(:verify!)

        strategy.expects(:decode_id_token).twice.with(access_token.id_token).returns(id_token)
        strategy.call!('rack.session' => { 'omniauth.state' => state })
        strategy.callback_phase
      end

      def test_callback_phase_with_id_token_no_kid
        other_rsa_private = OpenSSL::PKey::RSA.generate(2048)

        key = JSON::JWK.new(private_key)
        other_key = JSON::JWK.new(other_rsa_private)
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => jwt.to_s, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = issuer
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = { 'keys' => [other_key, key] }.to_json
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_id_token_with_kid
        other_rsa_private = OpenSSL::PKey::RSA.generate(2048)

        key = JSON::JWK.new(private_key)
        other_key = JSON::JWK.new(other_rsa_private)
        state = SecureRandom.hex(16)
        jwt_with_kid = JSON::JWT.new(payload).sign(key, :RS256)
        request.stubs(:params).returns('id_token' => jwt_with_kid.to_s, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = issuer
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = { 'keys' => [other_key, key] }.to_json
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_id_token_with_kid_and_no_matching_kid
        other_rsa_private = OpenSSL::PKey::RSA.generate(2048)

        key = JSON::JWK.new(private_key)
        other_key = JSON::JWK.new(other_rsa_private)
        state = SecureRandom.hex(16)
        jwt_with_kid = JSON::JWT.new(payload).sign(key, :RS256)
        request.stubs(:params).returns('id_token' => jwt_with_kid.to_s, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = issuer
        strategy.options.client_signing_alg = :RS256
        # We use private_key here instead of the wrapped key, which contains a kid
        strategy.options.client_jwk_signing_key = { 'keys' => [other_key, private_key] }.to_json
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        assert_raises JSON::JWK::Set::KidNotFound do
          strategy.callback_phase
        end
      end

      def test_callback_phase_with_id_token_with_hs256
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => jwt_with_hs256.to_s, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = issuer
        strategy.options.client_options.secret = hmac_secret
        strategy.options.client_signing_alg = :HS256
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_hs256_base64_jwt_secret
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => jwt_with_hs256.to_s, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = issuer
        strategy.options.jwt_secret_base64 = Base64.encode64(hmac_secret)
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_mismatched_signing_algorithm
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => jwt_with_hs512.to_s, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = issuer
        strategy.options.client_options.secret = hmac_secret
        strategy.options.client_signing_alg = :HS256
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        strategy.expects(:fail!).with(:invalid_jwt_algorithm, is_a(OmniAuth::Strategies::OpenIDConnect::CallbackError))
        strategy.callback_phase
      end

      def test_callback_phase_with_id_token_no_matching_key
        rsa_private = OpenSSL::PKey::RSA.generate(2048)
        other_rsa_private = OpenSSL::PKey::RSA.generate(2048)

        other_key = JSON::JWK.new(other_rsa_private)
        token = JSON::JWT.new(payload).sign(rsa_private, :RS256).to_s
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => token, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = issuer
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = { 'keys' => [other_key] }.to_json
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        assert_raises JSON::JWK::Set::KidNotFound do
          strategy.callback_phase
        end
      end

      def test_callback_phase_with_discovery # rubocop:disable Metrics/AbcSize
        state = SecureRandom.hex(16)

        request.stubs(:params).returns('code' => jwt.to_s, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.client_options.host = 'example.com'
        strategy.options.discovery = true

        issuer = stub('OpenIDConnect::Discovery::Issuer')
        issuer.stubs(:issuer).returns('https://example.com/')
        ::OpenIDConnect::Discovery::Provider.stubs(:discover!).returns(issuer)

        config = stub('OpenIDConnect::Discovery::Provder::Config')
        config.stubs(:authorization_endpoint).returns('https://example.com/authorization')
        config.stubs(:token_endpoint).returns('https://example.com/token')
        config.stubs(:userinfo_endpoint).returns('https://example.com/userinfo')
        config.stubs(:jwks_uri).returns('https://example.com/jwks')
        config.stubs(:jwks).returns(JSON::JWK::Set.new(jwks['keys']))

        ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:raw_attributes).returns('sub' => 'sub', 'name' => 'name', 'email' => 'email')
        id_token.stubs(:verify!).with(issuer: 'https://example.com/', client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        strategy.unstub(:user_info)
        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token)
        access_token.stubs(:refresh_token)
        access_token.stubs(:expires_in)
        access_token.stubs(:scope)
        access_token.stubs(:id_token).returns(jwt.to_s)
        client.expects(:access_token!).at_least_once.returns(access_token)
        access_token.expects(:userinfo!).returns(user_info)

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_no_state_without_state_verification # rubocop:disable Metrics/AbcSize
        code = SecureRandom.hex(16)

        strategy.options.require_state = false

        request.stubs(:params).returns('code' => code)
        request.stubs(:path).returns('')

        strategy.options.client_options.host = 'example.com'
        strategy.options.discovery = true

        issuer = stub('OpenIDConnect::Discovery::Issuer')
        issuer.stubs(:issuer).returns('https://example.com/')
        ::OpenIDConnect::Discovery::Provider.stubs(:discover!).returns(issuer)

        config = stub('OpenIDConnect::Discovery::Provder::Config')
        config.stubs(:authorization_endpoint).returns('https://example.com/authorization')
        config.stubs(:token_endpoint).returns('https://example.com/token')
        config.stubs(:userinfo_endpoint).returns('https://example.com/userinfo')
        config.stubs(:jwks_uri).returns('https://example.com/jwks')
        config.stubs(:jwks).returns(JSON::JWK::Set.new(jwks['keys']))

        ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:raw_attributes).returns('sub' => 'sub', 'name' => 'name', 'email' => 'email')
        id_token.stubs(:verify!).with(issuer: 'https://example.com/', client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        strategy.unstub(:user_info)
        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token)
        access_token.stubs(:refresh_token)
        access_token.stubs(:expires_in)
        access_token.stubs(:scope)
        access_token.stubs(:id_token).returns(jwt.to_s)
        client.expects(:access_token!).at_least_once.returns(access_token)
        access_token.expects(:userinfo!).returns(user_info)

        strategy.call!('rack.session' => { 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_invalid_state_without_state_verification
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)

        strategy.options.require_state = false

        request.stubs(:params).returns('code' => code, 'state' => 'foobar')
        request.stubs(:path).returns('')

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)
        strategy.callback_phase
      end

      def test_callback_phase_with_jwks_uri
        id_token = jwt.to_s
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => id_token, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = 'example.com'
        strategy.options.client_options.jwks_uri = 'https://jwks.example.com'
        strategy.options.response_type = 'id_token'

        HTTPClient
          .any_instance.stubs(:get_content)
          .with(strategy.options.client_options.jwks_uri)
          .returns(jwks.to_json)

        strategy.unstub(:user_info)
        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token)
        access_token.stubs(:refresh_token)
        access_token.stubs(:expires_in)
        access_token.stubs(:scope)
        access_token.stubs(:id_token).returns(id_token)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:raw_attributes).returns('sub' => 'sub', 'name' => 'name', 'email' => 'email')
        id_token.stubs(:verify!).with(issuer: strategy.options.issuer, client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)
        id_token.expects(:verify!)

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      def test_callback_phase_with_error
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('error' => 'invalid_request')
        request.stubs(:path).returns('')

        strategy.call!({ 'rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce } })
        strategy.expects(:fail!)
        strategy.callback_phase
      end

      def test_callback_phase_with_invalid_state
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => 'foobar')
        request.stubs(:path).returns('')

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)
        strategy.callback_phase
      end

      def test_callback_phase_without_code
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('state' => state)
        request.stubs(:path).returns('')

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        strategy.expects(:fail!).with(:missing_code, is_a(OmniAuth::OpenIDConnect::MissingCodeError))
        strategy.callback_phase
      end

      def test_callback_phase_without_id_token
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('state' => state)
        request.stubs(:path).returns('')
        strategy.options.response_type = 'id_token'

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        strategy.expects(:fail!).with(:missing_id_token, is_a(OmniAuth::OpenIDConnect::MissingIdTokenError))
        strategy.callback_phase
      end

      def test_callback_phase_without_id_token_symbol
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('state' => state)
        request.stubs(:path).returns('')
        strategy.options.response_type = :id_token

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        strategy.expects(:fail!).with(:missing_id_token, is_a(OmniAuth::OpenIDConnect::MissingIdTokenError))
        strategy.callback_phase
      end

      def test_callback_phase_with_timeout
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'

        strategy.stubs(:access_token).raises(::Timeout::Error.new('error'))
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).with(issuer: 'example.com', client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        strategy.callback_phase
      end

      def test_callback_phase_with_etimeout
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'

        strategy.stubs(:access_token).raises(::Errno::ETIMEDOUT.new('error'))
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).with(issuer: 'example.com', client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        strategy.callback_phase
      end

      def test_callback_phase_with_socket_error
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'

        strategy.stubs(:access_token).raises(::SocketError.new('error'))
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).with(issuer: 'example.com', client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        strategy.callback_phase
      end

      def test_callback_phase_with_rack_oauth2_client_error
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'

        strategy.stubs(:access_token).raises(::Rack::OAuth2::Client::Error.new('error', error: 'Unknown'))
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).with(issuer: 'example.com', client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        strategy.callback_phase
      end

      def test_info
        info = strategy.info
        assert_equal user_info.name, info[:name]
        assert_equal user_info.email, info[:email]
        assert_equal user_info.email_verified, info[:email_verified]
        assert_equal user_info.preferred_username, info[:nickname]
        assert_equal user_info.given_name, info[:first_name]
        assert_equal user_info.family_name, info[:last_name]
        assert_equal user_info.gender, info[:gender]
        assert_equal user_info.picture, info[:image]
        assert_equal user_info.phone_number, info[:phone]
        assert_equal({ website: user_info.website }, info[:urls])
      end

      def test_extra
        assert_equal({ raw_info: user_info.as_json }, strategy.extra)
      end

      def test_credentials
        strategy.options.issuer = 'example.com'
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = jwks.to_json

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token).returns(SecureRandom.hex(16))
        access_token.stubs(:refresh_token).returns(SecureRandom.hex(16))
        access_token.stubs(:expires_in).returns(Time.now)
        access_token.stubs(:scope).returns('openidconnect')
        access_token.stubs(:id_token).returns(jwt.to_s)

        client.expects(:access_token!).returns(access_token)
        access_token.expects(:refresh_token).returns(access_token.refresh_token)
        access_token.expects(:expires_in).returns(access_token.expires_in)

        assert_equal(
          {
            id_token: access_token.id_token,
            token: access_token.access_token,
            refresh_token: access_token.refresh_token,
            expires_in: access_token.expires_in,
            scope: access_token.scope,
          },
          strategy.credentials
        )
      end

      def test_option_send_nonce
        strategy.options.client_options[:host] = 'foobar.com'
        assert_match(/nonce/, strategy.authorize_uri, 'URI must contain nonce')

        strategy.options.send_nonce = false
        refute_match(/nonce/, strategy.authorize_uri, 'URI must not contain nonce')
      end

      def test_failure_endpoint_redirect
        OmniAuth.config.stubs(:failure_raise_out_environments).returns([])
        strategy.stubs(:env).returns({})
        request.stubs(:params).returns('error' => 'access denied')

        result = strategy.callback_phase

        assert(result.is_a?(Array))
        assert(result[0] == 302, 'Redirect')
        assert(result[1]['Location'] =~ %r{/auth/failure})
      end

      def test_state
        strategy.options.state = -> { 42 }

        expected_redirect = /&state=42/
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase

        session = { 'state' => 42 }
        # this should succeed as the correct state is passed with the request
        test_callback_phase(session, { 'state' => 42 })

        # the following should fail because the wrong state is passed to the callback
        code = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => 43)
        request.stubs(:path).returns('')

        strategy.call!('rack.session' => session)
        strategy.expects(:fail!)
        strategy.callback_phase
      end

      def test_dynamic_state
        # Stub request parameters
        request.stubs(:path).returns('')
        strategy.call!('rack.session' => {}, QUERY_STRING: { state: 'abc', client_id: '123' })

        strategy.options.state = lambda { |env|
          # Get params from request, e.g. CGI.parse(env['QUERY_STRING'])
          env[:QUERY_STRING][:state] + env[:QUERY_STRING][:client_id]
        }

        expected_redirect = /&state=abc123/
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end

      def test_option_client_auth_method
        state = SecureRandom.hex(16)

        opts = strategy.options.client_options
        opts[:host] = 'foobar.com'
        strategy.options.issuer = 'foobar.com'
        strategy.options.client_auth_method = :not_basic
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = jwks.to_json

        json_response = {
          access_token: 'test_access_token',
          id_token: jwt.to_s,
          token_type: 'Bearer',
        }.to_json
        success = Struct.new(:status, :body).new(200, json_response)

        request.stubs(:path).returns('')
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).with(issuer: strategy.options.issuer, client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

        HTTPClient.any_instance.stubs(:post).with(
          "#{ opts.scheme }://#{ opts.host }:#{ opts.port }#{ opts.token_endpoint }",
          { scope: 'openid', grant_type: :client_credentials, client_id: @identifier, client_secret: @secret },
          {}
        ).returns(success)

        assert(strategy.send(:access_token))
      end

      def test_public_key_with_jwks
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = jwks.to_json

        assert_equal JSON::JWK::Set, strategy.public_key.class
      end

      def test_public_key_with_jwk
        strategy.options.client_signing_alg = :RS256
        jwk = jwks[:keys].first
        strategy.options.client_jwk_signing_key = jwk.to_json

        assert_equal JSON::JWK, strategy.public_key.class
      end

      def test_public_key_with_x509
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_x509_signing_key = File.read('./test/fixtures/test.crt')
        assert_equal OpenSSL::PKey::RSA, strategy.public_key.class
      end

      def test_public_key_with_hmac
        strategy.options.client_options.secret = 'secret'
        strategy.options.client_signing_alg = :HS256
        assert_equal strategy.options.client_options.secret, strategy.secret
      end

      def test_id_token_auth_hash
        state = SecureRandom.hex(16)
        strategy.options.response_type = 'id_token'
        strategy.options.issuer = 'example.com'

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).returns(true)
        id_token.stubs(:raw_attributes, :to_h).returns(payload)

        request.stubs(:params).returns('state' => state, 'nounce' => nonce, 'id_token' => id_token)
        request.stubs(:path).returns('')

        strategy.stubs(:decode_id_token).returns(id_token)
        strategy.stubs(:stored_state).returns(state)

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase

        auth_hash = strategy.send(:env)['omniauth.auth']
        assert auth_hash.key?('provider')
        assert auth_hash.key?('uid')
        assert auth_hash.key?('info')
        assert auth_hash.key?('extra')
        assert auth_hash['extra'].key?('raw_info')
      end

      def test_option_pkce
        strategy.options.client_options[:host] = 'example.com'

        # test pkce disabled
        strategy.options.pkce = false

        assert((strategy.authorize_uri !~ /code_challenge=/), 'URI must not contain code challenge param')
        assert((strategy.authorize_uri !~ /code_challenge_method=/), 'URI must not contain code challenge method param')

        # test pkce enabled with default opts
        strategy.options.pkce = true

        assert(strategy.authorize_uri =~ /code_challenge=/, 'URI must contain code challenge param')
        assert(strategy.authorize_uri =~ /code_challenge_method=/, 'URI must contain code challenge method param')

        # test pkce with custom verifier code
        strategy.options.pkce_verifier = proc { 'dummy_verifier' }
        code_challenge_value = Base64.urlsafe_encode64(
          Digest::SHA2.digest(strategy.options.pkce_verifier.call),
          padding: false
        )

        assert(strategy.authorize_uri =~ /#{Regexp.quote(code_challenge_value)}/, 'URI must contain code challenge value')

        # test pkce with custom options and plain text code
        strategy.options.pkce_options =
          {
            code_challenge: proc { |verifier| verifier },
            code_challenge_method: 'plain',
          }

        assert(strategy.authorize_uri =~ /#{Regexp.quote(strategy.options.pkce_verifier.call)}/,
               'URI must contain code challenge value')
      end
    end
  end
end
