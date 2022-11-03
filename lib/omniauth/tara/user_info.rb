require 'openid_connect'

module OmniAuth
  module Tara
    class UserInfo
      attr_reader :id_token, :public_key

      def initialize(id_token, public_key)
        @id_token = id_token
        @public_key = public_key
      end

      def decoded_id_token
        @decoded_id_token ||= ::OpenIDConnect::ResponseObject::IdToken.decode(
          id_token, public_key
        )
      end

      def raw_attributes
        decoded_id_token.raw_attributes
      end

      def sub
        raw_attributes['sub']
      end

      def given_name
        raw_attributes.dig('profile_attributes', 'given_name')
      end

      def last_name
        raw_attributes.dig('profile_attributes', 'family_name')
      end

      def name
        sub
      end
    end
  end
end
