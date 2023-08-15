require 'openid_connect'

module OmniAuth
  module Tara
    class UserInfo < OpenIDConnect::ConnectObject
      attr_optional(
        :sub,
        :name,
        :nickname,
        :preferred_username,
        :profile,
        :locale,
        :email,
        :email_verified,
        :phone_number,
        :phone_number_verified,
        :profile_attributes,
      )
      alias subject sub
      alias subject= sub=

      validates :email_verified, :phone_number_verified, allow_nil: true, inclusion: { in: [true, false] }
      validates :email,                                  allow_nil: true, email: true
      validate :require_at_least_one_attributes

      def initialize(attributes = {})
        super
        (all_attributes - %i[email_verified phone_number_verified profile_attributes]).each do |key|
          send "#{key}=", send(key).try(:to_s)
        end
      end

      def given_name
        raw_attributes.dig('profile_attributes', 'given_name')
      end

      def family_name
        raw_attributes.dig('profile_attributes', 'family_name')
      end

      def birthdate
        raw_attributes.dig('profile_attributes', 'date_of_birth')
      end
    end
  end
end
