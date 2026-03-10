# frozen_string_literal: true

require 'test_helper'

class OpenIDConnectJweTest < StrategyTestCase
  # Builds a minimal RSA-OAEP-256 JWE token for round-trip testing.
  def build_rsa_oaep_256_jwe(plaintext, rsa_public_key, enc:)
    header = Base64.urlsafe_encode64({ alg: 'RSA-OAEP-256', enc: enc }.to_json, padding: false)

    cek_size = { 'A128GCM' => 16, 'A256GCM' => 32, 'A128CBC-HS256' => 32, 'A256CBC-HS512' => 64 }
    cek = SecureRandom.bytes(cek_size.fetch(enc))

    encrypted_cek = rsa_public_key.encrypt(
      cek,
      rsa_padding_mode: 'oaep',
      rsa_oaep_md: 'SHA256',
      rsa_mgf1_md: 'SHA256'
    )

    iv, ciphertext, auth_tag = encrypt_content(enc, cek, plaintext, header)

    [header,
     Base64.urlsafe_encode64(encrypted_cek, padding: false),
     Base64.urlsafe_encode64(iv, padding: false),
     Base64.urlsafe_encode64(ciphertext, padding: false),
     Base64.urlsafe_encode64(auth_tag, padding: false)].join('.')
  end

  def encrypt_content(enc, cek, plaintext, header)
    case enc
    when 'A128GCM', 'A256GCM'
      iv = SecureRandom.bytes(12)
      cipher = OpenSSL::Cipher.new(enc == 'A128GCM' ? 'aes-128-gcm' : 'aes-256-gcm')
      cipher.encrypt
      cipher.key = cek
      cipher.iv = iv
      cipher.auth_data = header.b
      ciphertext = cipher.update(plaintext) + cipher.final
      [iv, ciphertext, cipher.auth_tag]
    when 'A128CBC-HS256', 'A256CBC-HS512'
      key_half = enc == 'A128CBC-HS256' ? 16 : 32
      mac_key = cek[0, key_half]
      enc_key = cek[key_half, key_half]
      iv = SecureRandom.bytes(16)
      cipher = OpenSSL::Cipher.new(enc == 'A128CBC-HS256' ? 'aes-128-cbc' : 'aes-256-cbc')
      cipher.encrypt
      cipher.key = enc_key
      cipher.iv = iv
      ciphertext = cipher.update(plaintext) + cipher.final
      al = [header.bytesize * 8].pack('Q>')
      digest = OpenSSL::Digest.new(enc == 'A128CBC-HS256' ? 'SHA256' : 'SHA512')
      auth_tag = OpenSSL::HMAC.digest(digest, mac_key, header.b + iv + ciphertext + al)[0, key_half]
      [iv, ciphertext, auth_tag]
    end
  end

  # ---------------------------------------------------------------------------
  # #jwe?
  # ---------------------------------------------------------------------------

  def test_jwe_returns_false_when_alg_not_configured
    strategy.options.id_token_encryption_alg = nil
    refute strategy.send(:jwe?, 'a.b.c.d.e')
    refute strategy.send(:jwe?, 'a.b.c')
  end

  def test_jwe_returns_false_for_3_segment_token_even_with_alg_configured
    strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    refute strategy.send(:jwe?, 'a.b.c')
  end

  def test_jwe_returns_true_for_5_segment_token_with_alg_configured
    strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    assert strategy.send(:jwe?, 'a.b.c.d.e')
  end

  # ---------------------------------------------------------------------------
  # #decrypt_jwe - RSA-OAEP
  # ---------------------------------------------------------------------------

  def test_decrypt_jwe_rsa_oaep_raises_without_key
    strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    strategy.options.id_token_encryption_key = nil
    error = assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
    assert_includes error.error_reason, 'id_token_encryption_key'
  end

  def test_decrypt_jwe_rsa_oaep_delegates_to_json_jwe
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    strategy.options.id_token_encryption_key = rsa_key.to_pem

    mock_jwe = mock
    mock_jwe.stubs(:plain_text).returns('decrypted.jws.token')
    JSON::JWE.expects(:decode_compact_serialized)
             .with('a.b.c.d.e', instance_of(OpenSSL::PKey::RSA))
             .returns(mock_jwe)

    result = strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    assert_equal 'decrypted.jws.token', result
  end

  # ---------------------------------------------------------------------------
  # #decrypt_jwe - RSA-OAEP-256
  # ---------------------------------------------------------------------------

  def test_decrypt_jwe_rsa_oaep_256_raises_without_key
    strategy.options.id_token_encryption_alg = 'RSA-OAEP-256'
    strategy.options.id_token_encryption_key = nil
    assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
  end

  def test_decrypt_jwe_rsa_oaep_256_raises_for_malformed_pem
    strategy.options.id_token_encryption_alg = 'RSA-OAEP-256'
    strategy.options.id_token_encryption_key = 'not-a-valid-pem'
    assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
  end

  def test_decrypt_jwe_rsa_oaep_256_round_trip_a128gcm
    skip 'Requires OpenSSL >= 3.0' if OpenSSL::VERSION.split('.').first.to_i < 3

    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    plaintext = 'test.jws.payload'
    jwe_token = build_rsa_oaep_256_jwe(plaintext, rsa_key.public_key, enc: 'A128GCM')

    strategy.options.id_token_encryption_alg = 'RSA-OAEP-256'
    strategy.options.id_token_encryption_key = rsa_key.to_pem

    assert_equal plaintext, strategy.send(:decrypt_jwe, jwe_token)
  end

  def test_decrypt_jwe_rsa_oaep_256_round_trip_a128cbc_hs256
    skip 'Requires OpenSSL >= 3.0' if OpenSSL::VERSION.split('.').first.to_i < 3

    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    plaintext = 'test.jws.payload'
    jwe_token = build_rsa_oaep_256_jwe(plaintext, rsa_key.public_key, enc: 'A128CBC-HS256')

    strategy.options.id_token_encryption_alg = 'RSA-OAEP-256'
    strategy.options.id_token_encryption_key = rsa_key.to_pem

    assert_equal plaintext, strategy.send(:decrypt_jwe, jwe_token)
  end

  # ---------------------------------------------------------------------------
  # #decrypt_jwe - dir
  # ---------------------------------------------------------------------------

  def test_decrypt_jwe_dir_raises_without_key
    strategy.options.id_token_encryption_alg = 'dir'
    strategy.options.id_token_encryption_key = nil
    error = assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
    assert_includes error.error_reason, 'id_token_encryption_key'
  end

  def test_decrypt_jwe_dir_round_trip_a128cbc_hs256
    # A128CBC-HS256 requires a 32-byte CEK (16 mac + 16 enc)
    symmetric_key = SecureRandom.bytes(32)
    plaintext = 'test.jws.payload'
    header = Base64.urlsafe_encode64({ alg: 'dir', enc: 'A128CBC-HS256' }.to_json, padding: false)
    iv, ciphertext, auth_tag = encrypt_content('A128CBC-HS256', symmetric_key.b, plaintext, header)
    jwe_token = [
      header, '',
      Base64.urlsafe_encode64(iv, padding: false),
      Base64.urlsafe_encode64(ciphertext, padding: false),
      Base64.urlsafe_encode64(auth_tag, padding: false)
    ].join('.')

    strategy.options.id_token_encryption_alg = 'dir'
    strategy.options.id_token_encryption_key = symmetric_key

    assert_equal plaintext, strategy.send(:decrypt_jwe, jwe_token)
  end

  def test_decrypt_jwe_dir_round_trip_a128gcm
    symmetric_key = SecureRandom.bytes(16)
    plaintext = 'test.jws.payload'
    header = Base64.urlsafe_encode64({ alg: 'dir', enc: 'A128GCM' }.to_json, padding: false)
    iv, ciphertext, auth_tag = encrypt_content('A128GCM', symmetric_key, plaintext, header)
    jwe_token = [
      header, '',
      Base64.urlsafe_encode64(iv, padding: false),
      Base64.urlsafe_encode64(ciphertext, padding: false),
      Base64.urlsafe_encode64(auth_tag, padding: false)
    ].join('.')

    strategy.options.id_token_encryption_alg = 'dir'
    strategy.options.id_token_encryption_key = symmetric_key

    assert_equal plaintext, strategy.send(:decrypt_jwe, jwe_token)
  end

  # ---------------------------------------------------------------------------
  # #decrypt_jwe - unknown alg
  # ---------------------------------------------------------------------------

  def test_decrypt_jwe_unknown_alg_raises_callback_error
    strategy.options.id_token_encryption_alg = 'unsupported-alg'
    strategy.options.id_token_encryption_key = 'any'
    error = assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
    assert_includes error.error_reason, 'unsupported-alg'
  end

  # ---------------------------------------------------------------------------
  # #decrypt_jwe - error wrapping
  # ---------------------------------------------------------------------------

  def test_decrypt_jwe_wraps_decryption_failed
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    strategy.options.id_token_encryption_key = rsa_key.to_pem
    JSON::JWE.stubs(:decode_compact_serialized).raises(JSON::JWE::DecryptionFailed)
    assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
  end

  def test_decrypt_jwe_dir_wraps_malformed_token
    strategy.options.id_token_encryption_alg = 'dir'
    strategy.options.id_token_encryption_key = 'key'
    # Passing a malformed JWE to decrypt_dir triggers a JSON::ParserError on the header,
    # which is rescued and wrapped in a CallbackError.
    assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
  end

  def test_decrypt_jwe_wraps_argument_error
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    strategy.options.id_token_encryption_key = rsa_key.to_pem
    JSON::JWE.stubs(:decode_compact_serialized).raises(ArgumentError, 'invalid base64')
    assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, 'a.b.c.d.e')
    end
  end

  # ---------------------------------------------------------------------------
  # #decode_id_token integration
  # ---------------------------------------------------------------------------

  def test_decode_id_token_does_not_call_decrypt_jwe_for_3_segment_token
    strategy.expects(:decrypt_jwe).never
    strategy.send(:decode_id_token, 'header.payload.sig')
  rescue StandardError
    nil # super will fail without a full OIDC setup; we only care decrypt_jwe was not called
  end

  def test_decode_id_token_calls_decrypt_jwe_for_5_segment_token
    strategy.options.id_token_encryption_alg = 'dir'
    strategy.options.id_token_encryption_key = 'key'
    strategy.expects(:decrypt_jwe).with('h.e.i.c.t').returns('header.payload.sig')
    strategy.send(:decode_id_token, 'h.e.i.c.t')
  rescue StandardError
    nil # super will fail without a full OIDC setup; we only care decrypt_jwe was called
  end

  # ---------------------------------------------------------------------------
  # #user_info and #fetch_userinfo_attributes - encrypted userinfo endpoint
  # ---------------------------------------------------------------------------

  # A strategy instance without the default user_info stub, for testing user_info directly.
  def jwe_strategy
    @jwe_strategy ||= OmniAuth::Strategies::OpenIDConnect.new(DummyApp.new).tap do |s|
      s.options.client_options.identifier = @identifier
      s.options.client_options.secret = @secret
      s.stubs(:request).returns(request)
      s.stubs(:script_name).returns('')
    end
  end

  def test_user_info_uses_fetch_userinfo_attributes_when_encryption_configured
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    id_token_claims = { sub: 'user123', email: 'user@example.com', given_name: 'Ada' }
    id_token_jws = JSON::JWT.new(id_token_claims).sign(rsa_key, :RS256).to_s

    mock_access_token = stub(id_token: id_token_jws, http_client: stub)
    decoded = stub(raw_attributes: id_token_claims)

    jwe_strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    jwe_strategy.stubs(:access_token).returns(mock_access_token)
    jwe_strategy.stubs(:decode_id_token).with(id_token_jws).returns(decoded)
    jwe_strategy.stubs(:fetch_userinfo_attributes).returns({ sub: 'user123', phone_number: '+32499000000' })

    result = jwe_strategy.send(:user_info)
    assert_equal 'user123', result.sub
    assert_equal 'Ada', result.given_name
    assert_equal '+32499000000', result.phone_number
  end

  def test_user_info_falls_back_to_standard_path_when_no_encryption
    jwe_strategy.options.id_token_encryption_alg = nil
    mock_access_token = stub(id_token: nil)
    expected_userinfo = OpenIDConnect::ResponseObject::UserInfo.new(sub: 'user456')

    jwe_strategy.stubs(:access_token).returns(mock_access_token)
    mock_access_token.stubs(:userinfo!).returns(expected_userinfo)

    result = jwe_strategy.send(:user_info)
    assert_equal 'user456', result.sub
  end

  def test_fetch_userinfo_attributes_returns_hash_body_unchanged
    mock_http_client = stub
    mock_access_token = stub(http_client: mock_http_client)
    mock_client = stub(userinfo_uri: 'https://oidc.example.com/userinfo')
    body = { sub: 'user123', email: 'user@example.com' }

    jwe_strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    jwe_strategy.stubs(:access_token).returns(mock_access_token)
    jwe_strategy.stubs(:client).returns(mock_client)
    mock_http_client.stubs(:get).returns(stub(body: body))

    result = jwe_strategy.send(:fetch_userinfo_attributes)
    assert_equal body, result
  end

  def test_fetch_userinfo_attributes_decodes_plain_jwt_string_body
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    claims = { sub: 'user123', phone_number: '+32499000000' }
    jws = JSON::JWT.new(claims).sign(rsa_key, :RS256).to_s

    mock_http_client = stub
    mock_access_token = stub(http_client: mock_http_client)
    mock_client = stub(userinfo_uri: 'https://oidc.example.com/userinfo')

    jwe_strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    jwe_strategy.stubs(:access_token).returns(mock_access_token)
    jwe_strategy.stubs(:client).returns(mock_client)
    mock_http_client.stubs(:get).returns(stub(body: jws))

    result = jwe_strategy.send(:fetch_userinfo_attributes)
    assert_equal 'user123', result[:sub]
    assert_equal '+32499000000', result[:phone_number]
  end

  def test_fetch_userinfo_attributes_decrypts_jwe_string_body
    symmetric_key = SecureRandom.bytes(32)
    plaintext_claims = { sub: 'user123', phone_number: '+32499000000' }
    # Build a dir JWE wrapping a signed JWT
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    inner_jwt = JSON::JWT.new(plaintext_claims).sign(rsa_key, :RS256).to_s
    header = Base64.urlsafe_encode64({ alg: 'dir', enc: 'A128CBC-HS256' }.to_json, padding: false)
    iv, ciphertext, auth_tag = encrypt_content('A128CBC-HS256', symmetric_key.b, inner_jwt, header)
    jwe_body = [
      header, '',
      Base64.urlsafe_encode64(iv, padding: false),
      Base64.urlsafe_encode64(ciphertext, padding: false),
      Base64.urlsafe_encode64(auth_tag, padding: false)
    ].join('.')

    mock_http_client = stub
    mock_access_token = stub(http_client: mock_http_client)
    mock_client = stub(userinfo_uri: 'https://oidc.example.com/userinfo')

    jwe_strategy.options.id_token_encryption_alg = 'dir'
    jwe_strategy.options.id_token_encryption_key = symmetric_key
    jwe_strategy.stubs(:access_token).returns(mock_access_token)
    jwe_strategy.stubs(:client).returns(mock_client)
    mock_http_client.stubs(:get).returns(stub(body: jwe_body))

    result = jwe_strategy.send(:fetch_userinfo_attributes)
    assert_equal 'user123', result[:sub]
    assert_equal '+32499000000', result[:phone_number]
  end

  def test_fetch_userinfo_attributes_returns_empty_hash_on_decryption_error
    mock_http_client = stub
    mock_access_token = stub(http_client: mock_http_client)
    mock_client = stub(userinfo_uri: 'https://oidc.example.com/userinfo')

    jwe_strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    jwe_strategy.stubs(:access_token).returns(mock_access_token)
    jwe_strategy.stubs(:client).returns(mock_client)
    # A JWE-shaped body triggers decrypt_jwe which raises CallbackError on failure
    jwe_strategy.stubs(:jwe?).returns(true)
    jwe_strategy.stubs(:decrypt_jwe).raises(
      OmniAuth::Strategies::OpenIDConnect::CallbackError.new(error: :jwe_decryption_failed, reason: 'bad key')
    )
    mock_http_client.stubs(:get).returns(stub(body: 'a.b.c.d.e'))

    result = jwe_strategy.send(:fetch_userinfo_attributes)
    assert_equal({}, result)
  end

  def test_fetch_userinfo_attributes_propagates_network_errors
    mock_http_client = stub
    mock_access_token = stub(http_client: mock_http_client)
    mock_client = stub(userinfo_uri: 'https://oidc.example.com/userinfo')

    jwe_strategy.options.id_token_encryption_alg = 'RSA-OAEP'
    jwe_strategy.stubs(:access_token).returns(mock_access_token)
    jwe_strategy.stubs(:client).returns(mock_client)
    mock_http_client.stubs(:get).raises(StandardError, 'connection failed')

    assert_raises(StandardError) do
      jwe_strategy.send(:fetch_userinfo_attributes)
    end
  end

  def test_decrypt_dir_raises_on_wrong_key_length
    strategy.options.id_token_encryption_alg = 'dir'
    strategy.options.id_token_encryption_key = 'tooshort'

    symmetric_key = SecureRandom.bytes(32)
    header = Base64.urlsafe_encode64({ alg: 'dir', enc: 'A128CBC-HS256' }.to_json, padding: false)
    iv, ciphertext, auth_tag = encrypt_content('A128CBC-HS256', symmetric_key.b, 'payload', header)
    jwe_token = [
      header, '',
      Base64.urlsafe_encode64(iv, padding: false),
      Base64.urlsafe_encode64(ciphertext, padding: false),
      Base64.urlsafe_encode64(auth_tag, padding: false)
    ].join('.')

    error = assert_raises(OmniAuth::Strategies::OpenIDConnect::CallbackError) do
      strategy.send(:decrypt_jwe, jwe_token)
    end
    assert_includes error.error_reason, 'dir key must be 32 bytes'
  end
end
