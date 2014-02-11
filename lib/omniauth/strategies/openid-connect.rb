require 'omniauth'

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy

      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        scheme: "https",
        host: nil,
        port: 443,
        authorization_endpoint: "/authorize",
        token_endpoint: "/token",
        userinfo_endpoint: "/userinfo"
      }
      option :scope, "openid"
      option :response_type, "code"
      option :state
      option :response_mode
      option :display, nil#, [:page, :popup, :touch, :wap]
      option :prompt, nil#, [:none, :login, :consent, :select_account]
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :login_hint
      option :acr_values

      def option(name, value = nil, valid_values = nil)
        if valid_values.nil? || value.nil? || valid_values.include(value)
          super(name, value)
        else
          ArgumentError.new("#{valud} is not a valid value for #{name}. Valid values are #{valid_values.join(", ")}")
        end
      end

      def required_client_attributes
        { identifier: options.client_id }
      end

      def client_attributes
        options.client_options.merge({
          identifier: options.client_id,


        })
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_attributes)
      end

      def request_phase
        redirect "#{option.scheme}://#{option.host}:#{options.port}#{options.authorization_endpoint}"
      end
    end
  end
end

