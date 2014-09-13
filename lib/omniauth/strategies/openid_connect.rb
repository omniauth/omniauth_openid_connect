require 'addressable/uri'
require "net/http"
require 'omniauth'
require "openid_connect"

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
      option :send_nonce, true

      uid { user_info.sub }

      info do
        {
          name: user_info.name,
          email: user_info.email,
          nickname: user_info.preferred_username,
          first_name: user_info.given_name,
          last_name: user_info.family_name,
          gender: user_info.gender,
          image: user_info.picture,
          phone: user_info.phone_number,
          urls: { website: user_info.website }
        }
      end

      extra do
        { raw_info: user_info.raw_attributes }
      end

      credentials do
        {
          token: access_token.access_token,
          refresh_token: access_token.refresh_token,
          expires_in: access_token.expires_in,
          scope: access_token.scope
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def request_phase
        redirect authorize_uri
      end

      def callback_phase
        case
        when !request.params["code"]
          return fail!(:missing_code, OmniAuth::OpenIDConnect::MissingCodeError.new(request.params["error"]))
        when !session["state"].nil? && session["state"] != request.params["state"]
          return Rack::Response.new(['401 Unauthorized'], 401).finish
        end

        client.redirect_uri = client_options.redirect_uri
        client.authorization_code = authorization_code
        access_token
        super
      end

      def authorization_code
        request.params["code"]
      end

      def authorize_uri
        client.redirect_uri = client_options.redirect_uri
        opts = {
          response_type: options.response_type,
          scope: options.scope,
          nonce: (nonce if options.send_nonce),
          state: (session["state"] = options.state.call if options.state.respond_to? :call),
        }

        client.authorization_uri(opts.reject{|k,v| v.nil?})
      end

      private

      def user_info
        @user_info ||= access_token.userinfo!
      end

      def access_token
        @access_token ||= client.access_token!(scope: options.scope)
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
