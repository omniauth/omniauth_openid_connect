# frozen_string_literal: true

require_relative '../../../test_helper'

module OmniAuth
  module Strategies
    class NotYet
      # Implicit Flow
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

      def test_callback_phase_with_id_token
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('id_token' => code, 'state' => state)
        request.stubs(:path).returns('')

        strategy.options.issuer = 'example.com'
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = File.read('test/fixtures/jwks.json')
        strategy.options.response_type = 'id_token'

        strategy.unstub(:user_info)
        access_token = stub('OpenIDConnect::AccessToken')
        access_token.stubs(:access_token)
        access_token.stubs(:refresh_token)
        access_token.stubs(:expires_in)
        access_token.stubs(:scope)
        access_token.stubs(:id_token).returns(File.read('test/fixtures/id_token.txt'))

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:raw_attributes).returns('sub' => 'sub', 'name' => 'name', 'email' => 'email')
        id_token.stubs(:verify!).with(issuer: strategy.options.issuer, client_id: @identifier, nonce: nonce).returns(true)
        ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)
        id_token.expects(:verify!)

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.callback_phase
      end

      # Implicit Flow
      def test_callback_phase_without_id_token
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('state' => state)
        request.stubs(:path).returns('')
        strategy.options.response_type = 'id_token'

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        strategy.expects(:fail!).with(:missing_id_token, is_a(OmniAuth::OpenIDConnect::MissingIdTokenError))
        strategy.callback_phase
      end

      # Implicit Flow
      def test_callback_phase_without_id_token_symbol
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('state' => state)
        request.stubs(:path).returns('')
        strategy.options.response_type = :id_token

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })

        strategy.expects(:fail!).with(:missing_id_token, is_a(OmniAuth::OpenIDConnect::MissingIdTokenError))
        strategy.callback_phase
      end

      # Implicit Flow
      def test_id_token_auth_hash
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        strategy.options.response_type = 'token id_token'
        strategy.options.issuer = 'example.com'

        id_token = stub('OpenIDConnect::ResponseObject::IdToken')
        id_token.stubs(:verify!).returns(true)
        id_token.stubs(:raw_attributes, :to_h).returns(
          {
            "iss": 'http://server.example.com',
            "sub": '248289761001',
            "aud": 's6BhdRkqt3',
            "nonce": 'n-0S6_WzA2Mj',
            "exp": 1_311_281_970,
            "iat": 1_311_280_970,
          }
        )

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
    end
  end
end
