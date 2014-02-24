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
    subscriber_id = "1234"
    user_info = stub('OpenIDConnect::ResponseObject::UserInfo')
    user_info.expects(:sub).returns(subscriber_id)
    strategy.stubs(:user_info).returns(user_info)

    assert_equal subscriber_id, strategy.uid
  end

  def test_callback_phase
    redirect_uri = "https://example.com/auth/callback"
    code = SecureRandom.hex(16)
    request.stubs(:params).returns({"code" => code})
    request.stubs(:path_info).returns("")

    user_info = stub('OpenIDConnect::ResponseObject::UserInfo')
    user_info.expects(:sub)
    user_info.expects(:name)
    user_info.expects(:email)
    access_token = stub('OpenIDConnect::AccessToken')
    access_token.expects(:userinfo!).returns(user_info)

    client.expects(:access_token!).returns(access_token)

    strategy.call!({"rack.session" => {}})
    strategy.callback_phase
  end

  def test_info
    name = "Rorschach"
    email = "Rorschach@watchmen.com"
    user_info = stub('OpenIDConnect::ResponseObject::UserInfo')
    user_info.expects(:name).returns(name)
    user_info.expects(:email).returns(email)
    strategy.stubs(:user_info).returns(user_info)
    info = strategy.info

    assert_equal name, info[:name]
    assert_equal email, info[:email]
  end

end
