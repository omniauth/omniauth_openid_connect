require_relative '../../../test_helper'

class OmniAuth::Strategies::OpenIDConnectTest < StrategyTestCase
  def test_client_options_defaults
    assert_equal 'https', strategy.options.client_options.scheme
    assert_equal 443, strategy.options.client_options.port
    assert_equal '/authorize', strategy.options.client_options.authorization_endpoint
    assert_equal '/token', strategy.options.client_options.token_endpoint
  end

  def test_request_phase
    expected_redirect = /^https:\/\/example\.com\/authorize\?client_id=1234&nonce=[\w\d]{32}&response_type=code&scope=openid&state=[\w\d]{32}$/
    strategy.options.issuer = 'example.com'
    strategy.options.client_options.host = 'example.com'
    strategy.expects(:redirect).with(regexp_matches(expected_redirect))
    strategy.request_phase
  end

  def test_request_phase_with_discovery
    expected_redirect = /^https:\/\/example\.com\/authorization\?client_id=1234&nonce=[\w\d]{32}&response_type=code&scope=openid&state=[\w\d]{32}$/
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
  end

  def test_uid
    assert_equal user_info.sub, strategy.uid
  end

  def test_callback_phase
    code = SecureRandom.hex(16)
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    request.stubs(:params).returns({'code' => code,'state' => state})
    request.stubs(:path_info).returns('')

    strategy.options.issuer = 'example.com'

    id_token = stub('OpenIDConnect::ResponseObject::IdToken')
    id_token.stubs(:verify!).with({:issuer => strategy.options.issuer, :client_id => @identifier, :nonce => nonce}).returns(true)
    ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

    strategy.unstub(:user_info)
    access_token = stub('OpenIDConnect::AccessToken')
    access_token.stubs(:access_token)
    access_token.stubs(:refresh_token)
    access_token.stubs(:expires_in)
    access_token.stubs(:scope)
    access_token.stubs(:id_token).returns('id_token')
    client.expects(:access_token!).at_least_once.returns(access_token)
    access_token.expects(:userinfo!).returns(user_info)

    strategy.call!({'rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce}})
    strategy.callback_phase
  end

  def test_callback_phase_with_discovery
    code = SecureRandom.hex(16)
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    public_key = OpenSSL::PKey::RSA.generate(2048).public_key
    request.stubs(:params).returns({'code' => code,'state' => state})
    request.stubs(:path_info).returns('')

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
    config.stubs(:public_keys).returns([public_key])
    ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

    id_token = stub('OpenIDConnect::ResponseObject::IdToken')
    id_token.stubs(:verify!).with({:issuer => 'https://example.com/', :client_id => @identifier, :nonce => nonce}).returns(true)
    ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

    strategy.unstub(:user_info)
    access_token = stub('OpenIDConnect::AccessToken')
    access_token.stubs(:access_token)
    access_token.stubs(:refresh_token)
    access_token.stubs(:expires_in)
    access_token.stubs(:scope)
    access_token.stubs(:id_token).returns('id_token')
    client.expects(:access_token!).at_least_once.returns(access_token)
    access_token.expects(:userinfo!).returns(user_info)

    strategy.call!({'rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce}})
    strategy.callback_phase

  end

  def test_callback_phase_with_error
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    request.stubs(:params).returns({'error' => 'invalid_request'})
    request.stubs(:path_info).returns('')

    strategy.call!({'rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce}})
    strategy.expects(:fail!)
    strategy.callback_phase
  end

  def test_callback_phase_with_invalid_state
    code = SecureRandom.hex(16)
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    request.stubs(:params).returns({'code' => code,'state' => 'foobar'})
    request.stubs(:path_info).returns('')

    strategy.call!({'rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce}})
    strategy.expects(:fail!)
    strategy.callback_phase
  end

  def test_callback_phase_with_timeout
    code = SecureRandom.hex(16)
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    public_key = OpenSSL::PKey::RSA.generate(2048).public_key
    request.stubs(:params).returns({'code' => code,'state' => state})
    request.stubs(:path_info).returns('')

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
    config.stubs(:public_keys).returns([public_key])
    ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

    id_token = stub('OpenIDConnect::ResponseObject::IdToken')
    id_token.stubs(:verify!).with({:issuer => 'https://example.com/', :client_id => @identifier, :nonce => nonce}).returns(true)
    ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

    strategy.stubs(:access_token).raises(::Timeout::Error.new('error'))
    strategy.call!({'rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce}})
    strategy.expects(:fail!)
    strategy.callback_phase
  end

  def test_callback_phase_with_etimeout
    code = SecureRandom.hex(16)
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    public_key = OpenSSL::PKey::RSA.generate(2048).public_key
    request.stubs(:params).returns({'code' => code,'state' => state})
    request.stubs(:path_info).returns('')

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
    config.stubs(:public_keys).returns([public_key])
    ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

    id_token = stub('OpenIDConnect::ResponseObject::IdToken')
    id_token.stubs(:verify!).with({:issuer => 'https://example.com/', :client_id => @identifier, :nonce => nonce}).returns(true)
    ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

    strategy.stubs(:access_token).raises(::Errno::ETIMEDOUT.new('error'))
    strategy.call!({'rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce}})
    strategy.expects(:fail!)
    strategy.callback_phase
  end

  def test_callback_phase_with_socket_error
    code = SecureRandom.hex(16)
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    public_key = OpenSSL::PKey::RSA.generate(2048).public_key
    request.stubs(:params).returns({'code' => code,'state' => state})
    request.stubs(:path_info).returns('')

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
    config.stubs(:public_keys).returns([public_key])
    ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com/').returns(config)

    id_token = stub('OpenIDConnect::ResponseObject::IdToken')
    id_token.stubs(:verify!).with({:issuer => 'https://example.com/', :client_id => @identifier, :nonce => nonce}).returns(true)
    ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

    strategy.stubs(:access_token).raises(::SocketError.new('error'))
    strategy.call!({'rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce}})
    strategy.expects(:fail!)
    strategy.callback_phase
  end

  def test_info
    info = strategy.info
    assert_equal user_info.name, info[:name]
    assert_equal user_info.email, info[:email]
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

    id_token = stub('OpenIDConnect::ResponseObject::IdToken')
    id_token.stubs(:verify!).returns(true)
    ::OpenIDConnect::ResponseObject::IdToken.stubs(:decode).returns(id_token)

    access_token = stub('OpenIDConnect::AccessToken')
    access_token.stubs(:access_token).returns(SecureRandom.hex(16))
    access_token.stubs(:refresh_token).returns(SecureRandom.hex(16))
    access_token.stubs(:expires_in).returns(Time.now)
    access_token.stubs(:scope).returns('openidconnect')
    access_token.stubs(:id_token).returns(id_token)

    client.expects(:access_token!).returns(access_token)
    access_token.expects(:refresh_token).returns(access_token.refresh_token)
    access_token.expects(:expires_in).returns(access_token.expires_in)

    assert_equal({ id_token: access_token.id_token,
                   token: access_token.access_token,
                   refresh_token: access_token.refresh_token,
                   expires_in: access_token.expires_in,
                   scope: access_token.scope
                 }, strategy.credentials)
  end

  def test_public_key_with_jwk
    strategy.options.client_signing_alg = :RS256
    strategy.options.client_jwk_signing_key = File.read('./test/fixtures/jwks.json')
    assert_equal OpenSSL::PKey::RSA, strategy.public_key.class
  end

  def test_public_key_with_x509
    strategy.options.client_signing_alg = :RS256
    strategy.options.client_x509_signing_key = File.read('./test/fixtures/test.crt')
    assert_equal OpenSSL::X509::Certificate, strategy.public_key.class
  end

  def test_public_key_with_hmac
    strategy.options.client_options.secret = 'secret'
    strategy.options.client_signing_alg = :HS256
    assert_equal strategy.options.client_options.secret, strategy.public_key
  end
end
