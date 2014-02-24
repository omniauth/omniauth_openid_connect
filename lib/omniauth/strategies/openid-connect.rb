require 'addressable/uri'
require "net/http"
require 'omniauth'
require "openid_connect"

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy

      attr_accessor :access_token

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
      option :scope, [:openid]
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

      uid { user_info.sub }

      info do
        {
          name: user_info.name,
          email: user_info.email,
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def request_phase
        redirect authorize_uri
      end

      def callback_phase
        client.redirect_uri = client_options.redirect_uri
        client.authorization_code = authorization_code
        @access_token = client.access_token!
        super
      end

      def authorization_code
        request.params["code"]
      end

      private

      def user_info
        @user_info ||= access_token.userinfo!
      end

      def authorize_uri
        client.redirect_uri = client_options.redirect_uri
        client.authorization_uri(
          response_type: options.response_type,
          scope: options.scope,
          nonce: nonce,
        )
      end

      def client_options
        options.client_options
      end

      def nonce
        session[:nonce] = SecureRandom.hex(16)
      end

      def session
        @env.nil? ? {} : super
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
