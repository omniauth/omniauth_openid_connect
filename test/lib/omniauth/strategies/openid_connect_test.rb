require_relative '../../../test_helper'

class OmniAuth::Strategies::OpenIDConnectTest < StrategyTestCase
  def test_client_options_defaults
    assert_equal "https", strategy.options.client_options.scheme
    assert_equal 443, strategy.options.client_options.port
    assert_equal "/authorize", strategy.options.client_options.authorization_endpoint
    assert_equal "/token", strategy.options.client_options.token_endpoint
  end

  def test_request_phase
    expected_redirect = /^https:\/\/example\.com\/authorize\?client_id=1234&nonce=[\w\d]{32}&response_type=code&scope=openid$/
    strategy.options.client_options.host = "example.com"
    strategy.expects(:redirect).with(regexp_matches(expected_redirect))
    strategy.request_phase
  end

  def test_uid
    assert_equal user_info.sub, strategy.uid
  end

  def test_callback_phase
    code = SecureRandom.hex(16)
    request.stubs(:params).returns({"code" => code})
    request.stubs(:path_info).returns("")

    strategy.unstub(:user_info)
    access_token = stub('OpenIDConnect::AccessToken')
    access_token.stubs(:access_token)
    client.expects(:access_token!).returns(access_token)
    access_token.expects(:userinfo!).returns(user_info)

    strategy.call!({"rack.session" => {}})
    strategy.callback_phase
  end

  def test_info
    info = strategy.info
    assert_equal user_info.name, info[:name]
    assert_equal user_info.email, info[:email]
    assert_equal user_info.preferred_username, info[:nickname]
    assert_equal user_info.given_name, info[:first_name]
    assert_equal user_info.family_name, info[:last_name]
    assert_equal user_info.picture, info[:image]
    assert_equal user_info.phone_number, info[:phone]
    assert_equal({ website: user_info.website }, info[:urls])
  end

  def test_extra
    assert_equal({ raw_info: user_info.as_json }, strategy.extra)
  end

  def test_credentials
    access_token = stub('OpenIDConnect::AccessToken')
    access_token.stubs(:access_token).returns(SecureRandom.hex(16))
    client.expects(:access_token!).returns(access_token)

    assert_equal({ token: access_token.access_token }, strategy.credentials)
  end
end
