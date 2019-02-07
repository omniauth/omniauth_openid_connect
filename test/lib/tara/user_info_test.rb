require_relative '../../test_helper'

module OmniAuth
  module Tara
    class UserInfoTest < Minitest::Test
      def setup
        @public_key = JSON::JWK::Set.new([
          {"kty": "RSA",
           "kid": "de6cc4",
           "n":
           "jWwAjT_03ypme9ZWeSe7c-jY26NO50Wo5I1LBnPW2JLc0dPMj8v7y4ehiRpClYNTaSWcLd4DJmlKXDXXudEUWwXa7TtjBFJfzlZ-1u0tDvJ-H9zv9MzO7UhUFytztUEMTrtStdhGbzkzdEZZCgFYeo2i33eXxzIR1nGvI05d9Y-e_LHnNE2ZKTa89BC7ZiCXq5nfAaCgQna_knh4kFAX-KgiPRAtsiDHcAWKcBY3qUVcb-5XAX8p668MlGLukzsh5tFkQCbJVyNtmlbIHdbGvVHPb8C0H3oLYciv1Fjy_tS1lO7OT_cb3GVp6Ql-CG0uED_8pkpVtfsGRviub4_ElQ",
           "e": "AQAB"}
        ])

        @id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlNmNjNCJ9.eyJqdGkiOiIxMTA5YTIyOS1mZWIwLTQ3OWEtOTRlZS03NTY0MGRkNmJiMGMiLCJpc3MiOiJodHRwczovL3RhcmEtdGVzdC5yaWEuZWUiLCJhdWQiOiJyZWdpc3RyZWVyaWphIiwiZXhwIjoxNTQ5NTc0MjczLCJpYXQiOjE1NDk1NDU0NzMsIm5iZiI6MTU0OTU0NTE3Mywic3ViIjoiRUUxMDEwMTAxMDAwNSIsInByb2ZpbGVfYXR0cmlidXRlcyI6eyJkYXRlX29mX2JpcnRoIjoiMTgwMS0wMS0wMSIsImZhbWlseV9uYW1lIjoiU01BUlQtSUQiLCJnaXZlbl9uYW1lIjoiREVNTyJ9LCJhbXIiOlsic21hcnRpZCJdLCJzdGF0ZSI6IjczMmNmY2IxMjZiYWY3MWMyZmI5Iiwibm9uY2UiOiIwZjhlYjI5NjBkMDJjMmY3NjU1ZjBmOWMwMTZhZDlhYiIsImF0X2hhc2giOiJ6eDhFNDBjY3NKTTEzM2dSZzVWLzNnPT0ifQ.TdYwVag4Miflg1PqeEF4ARJRptGxw8UqqcycXaqeD-gdbfzQ7nHo0N-3OYPe7S92o11ymh_FWZnKdYp7mGHzR7jyMYr4MXUkbHRZHTdO0jyZ9fEcn9lvS4mZh04o81LaVjeiPt7PGEVpaJp8CVs7IJPlZ8CgH5XPHAXZni5hJX--lJsDUoF467EcgCnwJishUZgE3TOv0t1ZkdzBPNq2ipYE5Ctg50AAVWzpG4ZT-9UrRP3v5raKeC3PvaiGfab66ELcbx2BtkLDpeD7aDG0jNrFPBN4Ta5iF2KuZXd2ICBLao0UQlmiCTWXL0xYAEuOvOD82MFtwZqddWNGRjIZlQ"
      end

      def test_initialize
        instance = OmniAuth::Tara::UserInfo.new(:id_token, :public_key)

        assert_equal(instance.id_token, :id_token)
        assert_equal(instance.public_key, :public_key)
      end

      def test_attributes
        instance = OmniAuth::Tara::UserInfo.new(@id_token, @public_key)

        assert_equal("EE10101010005", instance.sub)
        assert_equal("SMART-ID", instance.last_name)
        assert_equal("DEMO", instance.given_name)
        assert_equal(instance.name, instance.sub)
      end
    end
  end
end
