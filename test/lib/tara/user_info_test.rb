require_relative '../../test_helper'

module OmniAuth
  module Tara
    class UserInfoTest < Minitest::Test
      def setup
        file = File.read('./test/fixtures/jwks.json')
        @public_key = JSON::JWK::Set.new(JSON.parse(file))
        @id_token = File.read('./test/fixtures/id_token.txt')
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
