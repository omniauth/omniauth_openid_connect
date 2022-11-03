class StrategyTestCase < MiniTest::Test
  class DummyApp
    def call(env); end
  end

  attr_accessor :identifier, :secret

  def setup
    @identifier = '1234'
    @secret = '1234asdgat3'

    @public_key = JSON::JWK::Set.new([
      {"kty": "RSA",
       "kid": "de6cc4",
       "n":
       "jWwAjT_03ypme9ZWeSe7c-jY26NO50Wo5I1LBnPW2JLc0dPMj8v7y4ehiRpClYNTaSWcLd4DJmlKXDXXudEUWwXa7TtjBFJfzlZ-1u0tDvJ-H9zv9MzO7UhUFytztUEMTrtStdhGbzkzdEZZCgFYeo2i33eXxzIR1nGvI05d9Y-e_LHnNE2ZKTa89BC7ZiCXq5nfAaCgQna_knh4kFAX-KgiPRAtsiDHcAWKcBY3qUVcb-5XAX8p668MlGLukzsh5tFkQCbJVyNtmlbIHdbGvVHPb8C0H3oLYciv1Fjy_tS1lO7OT_cb3GVp6Ql-CG0uED_8pkpVtfsGRviub4_ElQ",
       "e": "AQAB"}
    ])

    @id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlNmNjNCJ9.eyJqdGkiOiIxMTA5YTIyOS1mZWIwLTQ3OWEtOTRlZS03NTY0MGRkNmJiMGMiLCJpc3MiOiJodHRwczovL3RhcmEtdGVzdC5yaWEuZWUiLCJhdWQiOiJyZWdpc3RyZWVyaWphIiwiZXhwIjoxNTQ5NTc0MjczLCJpYXQiOjE1NDk1NDU0NzMsIm5iZiI6MTU0OTU0NTE3Mywic3ViIjoiRUUxMDEwMTAxMDAwNSIsInByb2ZpbGVfYXR0cmlidXRlcyI6eyJkYXRlX29mX2JpcnRoIjoiMTgwMS0wMS0wMSIsImZhbWlseV9uYW1lIjoiU01BUlQtSUQiLCJnaXZlbl9uYW1lIjoiREVNTyJ9LCJhbXIiOlsic21hcnRpZCJdLCJzdGF0ZSI6IjczMmNmY2IxMjZiYWY3MWMyZmI5Iiwibm9uY2UiOiIwZjhlYjI5NjBkMDJjMmY3NjU1ZjBmOWMwMTZhZDlhYiIsImF0X2hhc2giOiJ6eDhFNDBjY3NKTTEzM2dSZzVWLzNnPT0ifQ.TdYwVag4Miflg1PqeEF4ARJRptGxw8UqqcycXaqeD-gdbfzQ7nHo0N-3OYPe7S92o11ymh_FWZnKdYp7mGHzR7jyMYr4MXUkbHRZHTdO0jyZ9fEcn9lvS4mZh04o81LaVjeiPt7PGEVpaJp8CVs7IJPlZ8CgH5XPHAXZni5hJX--lJsDUoF467EcgCnwJishUZgE3TOv0t1ZkdzBPNq2ipYE5Ctg50AAVWzpG4ZT-9UrRP3v5raKeC3PvaiGfab66ELcbx2BtkLDpeD7aDG0jNrFPBN4Ta5iF2KuZXd2ICBLao0UQlmiCTWXL0xYAEuOvOD82MFtwZqddWNGRjIZlQ"
  end

  def client
    strategy.client
  end

  def user_info
    @user_info ||= OmniAuth::Tara::UserInfo.new(@id_token, @public_key)
  end

  def request
    @request ||= stub('Request').tap do |request|
      request.stubs(:params).returns({})
      request.stubs(:cookies).returns({})
      request.stubs(:env).returns({})
      request.stubs(:scheme).returns({})
      request.stubs(:ssl?).returns(false)
      request.stubs(:path).returns('')
    end
  end

  # rubocop:disable Style/StringLiterals
  def id_token_raw_attributes
    { "jti" => "1109a229-feb0-479a-94ee-75640dd6bb0c",
      "iss" => "https://tara-test.ria.ee",
      "aud" => "registreerija",
      "exp" => 154_957_427_3,
      "iat" => 154_954_547_3,
      "nbf" => 154_954_517_3,
      "sub" => "EE10101010005",
      "profile_attributes" => { "date_of_birth" => "1801-01-01",
                                "family_name" => "SMART-ID", "given_name" => "DEMO" },
      "amr" => ["smartid"],
      "state" => "732cfcb126baf71c2fb9",
      "nonce" => "0f8eb2960d02c2f7655f0f9c016ad9ab",
      "at_hash" => "zx8E40ccsJM133gRg5V/3g==" }
  end
  # rubocop:enable Style/StringLiterals

  def strategy
    @strategy ||= OmniAuth::Strategies::Tara.new(DummyApp.new).tap do |strategy|
      strategy.options.client_options.identifier = @identifier
      strategy.options.client_options.secret = @secret
      strategy.stubs(:request).returns(request)
      strategy.stubs(:user_info).returns(user_info)
      strategy.stubs(:script_name).returns('')
    end
  end
end
