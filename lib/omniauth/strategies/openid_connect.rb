# frozen_string_literal: true

require 'addressable/uri'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'
require 'forwardable'

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy
      extend Forwardable

      def_delegator :request, :params

      option :name, 'openid_connect'
      option(:client_options, identifier: nil,
                              secret: nil,
                              redirect_uri: nil,
                              scheme: 'https',
                              host: nil,
                              port: 443,
                              authorization_endpoint: '/authorize',
                              token_endpoint: '/token',
                              userinfo_endpoint: '/userinfo',
                              jwks_uri: '/jwk',
                              end_session_endpoint: nil)

      #  Custom configuration
      option :discovery, false
      option :display # [:page, :popup, :touch, :wap]
      option :uid_field, 'sub'

      # OpenID Connect Core 1.0 (Final) Specification
      # https://openid.net/specs/openid-connect-core-1_0.html
      option :acr_values
      option :claims
      option :claims_locales
      option :client_auth_method, :basic # https://github.com/nov/rack-oauth2/blob/master/lib/rack/oauth2/client.rb#L84
      option :client_jwk_signing_key
      option :client_signing_alg
      option :client_x509_signing_key
      option :id_token_hint
      option :issuer
      option :max_age
      option :prompt # [:none, :login, :consent, :select_account]
      option :response_mode
      option :response_type, :code
      option :scope, [:openid]
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :state
      option :ui_locales

      # OpenID Connect Session Management 1.0 (draft 28) Specification
      # https://openid.net/specs/openid-connect-session-1_0.html
      option :post_logout_redirect_uri

      # Google specific
      # https://developers.google.com/identity/protocols/OpenIDConnect#authenticationuriparameters
      option :google_hd

      def uid
        user_info.public_send(options.uid_field.to_s)
      rescue NoMethodError
        log :warn, "User sub:#{user_info.sub} missing info field: #{options.uid_field}"
        user_info.sub
      end

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
          urls: { website: user_info.website },
        }
      end

      extra do
        { raw_info: user_info.raw_attributes }
      end

      credentials do
        {
          id_token: access_token.id_token,
          token: access_token.access_token,
          refresh_token: access_token.refresh_token,
          expires_in: access_token.expires_in,
          scope: access_token.scope,
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def config
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)
      end

      def request_phase
        options.issuer = issuer if options.issuer.to_s.empty?
        discover!
        redirect authorize_uri
      end

      def callback_phase
        error = params['error_reason'] || params['error']
        error_description = params['error_description'] || params['error_reason']
        invalid_state = params['state'].to_s.empty? || params['state'] != stored_state

        raise CallbackError.new(params['error'], error_description, params['error_uri']) if error

        raise CallbackError, 'Invalid state parameter' if invalid_state

        return fail!(:missing_code, OmniAuth::OpenIDConnect::MissingCodeError.new(params['error'])) unless params['code']

        options.issuer = issuer if options.issuer.nil? || options.issuer.empty?
        discover!
        client.redirect_uri = redirect_uri
        client.authorization_code = authorization_code
        access_token
        super
      rescue CallbackError, ::Rack::OAuth2::Client::Error => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def other_phase
        if logout_path_pattern === current_path
          options.issuer = issuer if options.issuer.to_s.empty?
          discover!
          return redirect(end_session_uri) if end_session_uri
        end
        call_app!
      end

      def authorization_code
        params['code']
      end

      def end_session_uri
        return unless end_session_endpoint_is_valid?

        end_session_uri = URI(client_options.end_session_endpoint)
        end_session_uri.query = encoded_post_logout_redirect_uri
        end_session_uri.to_s
      end

      def authorize_uri
        claims = params['claims'] || options.claims
        claims = claims ? JSON.dump(claims) : nil
        client.redirect_uri = redirect_uri
        opts = {
          claims: claims,
          claims_locales: params['claims_locales'] || options.claims_locales,
          google_hd: params['google_hd'] || options.google_hd,
          login_hint: params['login_hint'] || options.login_hint,
          nonce: (new_nonce if params['send_nonce'] || options.send_nonce),
          prompt: params['prompt'] || options.prompt,
          response_type: params['response_type'] || options.response_type,
          scope: params['scope'] || options.scope,
          state: new_state,
          ui_locales: params['ui_locales'] || options.ui_locales,
        }
        client.authorization_uri(opts.reject { |_k, v| v.nil? })
      end

      def public_key
        return config.jwks if options.discovery

        key_or_secret
      end

      private

      def issuer
        resource = "#{ client_options.scheme }://#{ client_options.host }"
        resource = "#{ resource }:#{ client_options.port }" if client_options.port
        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        return unless options.discovery

        client_options.authorization_endpoint = config.authorization_endpoint
        client_options.token_endpoint = config.token_endpoint
        client_options.userinfo_endpoint = config.userinfo_endpoint
        client_options.jwks_uri = config.jwks_uri
        client_options.end_session_endpoint = config.end_session_endpoint if config.respond_to?(:end_session_endpoint)
      end

      def user_info
        @user_info ||= access_token.userinfo!
      end

      def access_token
        return @access_token if @access_token

        @access_token = client.access_token!(
          scope: (options.scope if options.send_scope_to_token_endpoint),
          client_auth_method: options.client_auth_method
        )
        id_token = decode_id_token(@access_token.id_token)
        id_token.verify!(
          issuer: options.issuer,
          client_id: client_options.identifier,
          nonce: stored_nonce
        )
        @access_token
      end

      def decode_id_token(id_token)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, public_key)
      end

      def client_options
        options.client_options
      end

      def new_state
        state = if options.state.respond_to?(:call)
                  if options.state.arity == 1
                    options.state.call(env)
                  else
                    options.state.call
                  end
                end
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def session
        return {} if @env.nil?

        super
      end

      def key_or_secret
        case options.client_signing_alg
        when :HS256, :HS384, :HS512
          client_options.secret
        when :RS256, :RS384, :RS512
          if options.client_jwk_signing_key
            parse_jwk_key(options.client_jwk_signing_key)
          elsif options.client_x509_signing_key
            parse_x509_key(options.client_x509_signing_key)
          end
        end
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end

      def parse_jwk_key(key)
        json = JSON.parse(key)
        return JSON::JWK::Set.new(json['keys']) if json.key?('keys')

        JSON::JWK.new(json)
      end

      def decode(str)
        UrlSafeBase64.decode64(str).unpack1('B*').to_i(2).to_s
      end

      def redirect_uri
        return client_options.redirect_uri unless params['redirect_uri']

        "#{ client_options.redirect_uri }?redirect_uri=#{ CGI.escape(params['redirect_uri']) }"
      end

      def encoded_post_logout_redirect_uri
        return unless options.post_logout_redirect_uri

        URI.encode_www_form(
          post_logout_redirect_uri: options.post_logout_redirect_uri
        )
      end

      def end_session_endpoint_is_valid?
        client_options.end_session_endpoint &&
          client_options.end_session_endpoint =~ URI::DEFAULT_PARSER.make_regexp
      end

      def logout_path_pattern
        @logout_path_pattern ||= %r{\A#{Regexp.quote(request_path)}(/logout)}
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
