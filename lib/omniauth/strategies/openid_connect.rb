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

      RESPONSE_TYPE_EXCEPTIONS = {
        'id_token' => { exception_class: OmniAuth::OpenIDConnect::MissingIdTokenError, key: :missing_id_token }.freeze,
        'code' => { exception_class: OmniAuth::OpenIDConnect::MissingCodeError, key: :missing_code }.freeze,
      }.freeze

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

      option :issuer
      option :discovery, false
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, 'code' # ['code', 'id_token']
      option :state
      option :response_mode # [:query, :fragment, :form_post, :web_message]
      option :display, nil # [:page, :popup, :touch, :wap]
      option :prompt, nil # [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :acr_values
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method
      option :post_logout_redirect_uri
      option :extra_authorize_params, {}
      option :uid_field, 'sub'
      option :pkce, false
      option :pkce_verifier, nil
      option :pkce_options, {
        code_challenge: proc { |verifier|
          Base64.urlsafe_encode64(
            Digest::SHA2.digest(verifier),
            padding: false,
            )
        },
        code_challenge_method: "S256",
      }

      def uid
        user_info.raw_attributes[options.uid_field.to_sym] || user_info.sub
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

        raise CallbackError, error: params['error'], reason: error_description, uri: params['error_uri'] if error
        raise CallbackError, error: :csrf_detected, reason: "Invalid 'state' parameter" if invalid_state

        return unless valid_response_type?

        options.issuer = issuer if options.issuer.nil? || options.issuer.empty?

        verify_id_token!(params['id_token']) if configured_response_type == 'id_token'
        discover!
        client.redirect_uri = redirect_uri

        return id_token_callback_phase if configured_response_type == 'id_token'

        client.authorization_code = authorization_code
        access_token
        super
      rescue CallbackError => e
        fail!(e.error, e)
      rescue ::Rack::OAuth2::Client::Error => e
        fail!(e.response[:error], e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def other_phase
        if logout_path_pattern.match?(current_path)
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
        client.redirect_uri = redirect_uri
        opts = {
          response_type: options.response_type,
          response_mode: options.response_mode,
          scope: options.scope,
          state: new_state,
          login_hint: params['login_hint'],
          ui_locales: params['ui_locales'],
          claims_locales: params['claims_locales'],
          prompt: options.prompt,
          nonce: (new_nonce if options.send_nonce),
          hd: options.hd,
          acr_values: options.acr_values,
        }

        opts.merge!(options.extra_authorize_params) unless options.extra_authorize_params.empty?

        if options.pkce
          opts.merge!(pkce_authorize_params)
          session["omniauth.pkce.verifier"] = options.pkce_verifier
        end

        client.authorization_uri(opts.reject { |_k, v| v.nil? })
      end

      def public_key
        return config.jwks if options.discovery

        key_or_secret
      end

      def pkce_authorize_params
        options.pkce_verifier = SecureRandom.hex(64) if options.pkce_verifier.nil?

        # NOTE: see https://tools.ietf.org/html/rfc7636#appendix-A
        {
          :code_challenge => options.pkce_options[:code_challenge].call(options.pkce_verifier),
          :code_challenge_method => options.pkce_options[:code_challenge_method],
        }
      end

      def pkce_token_params
        return {} unless options.pkce

        {:code_verifier => session.delete("omniauth.pkce.verifier")}
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
        return @user_info if @user_info

        if access_token.id_token
          decoded = decode_id_token(access_token.id_token).raw_attributes

          @user_info = ::OpenIDConnect::ResponseObject::UserInfo.new access_token.userinfo!.raw_attributes.merge(decoded)
        else
          @user_info = access_token.userinfo!
        end
      end

      def access_token
        return @access_token if @access_token

        @access_token = client.access_token!(
          scope: (options.scope if options.send_scope_to_token_endpoint),
          client_auth_method: options.client_auth_method,
          code_verifier: (session.delete("omniauth.pkce.verifier") if options.pkce)
        )

        verify_id_token!(@access_token.id_token) if configured_response_type == 'code'

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

      def id_token_callback_phase
        user_data = decode_id_token(params['id_token']).raw_attributes
        env['omniauth.auth'] = AuthHash.new(
          provider: name,
          uid: user_data['sub'],
          info: { name: user_data['name'], email: user_data['email'] },
          extra: { raw_info: user_data }
        )
        call_app!
      end

      def valid_response_type?
        return true if params.key?(configured_response_type)

        error_attrs = RESPONSE_TYPE_EXCEPTIONS[configured_response_type]
        fail!(error_attrs[:key], error_attrs[:exception_class].new(params['error']))

        false
      end

      def configured_response_type
        @configured_response_type ||= options.response_type.to_s
      end

      def verify_id_token!(id_token)
        return unless id_token

        decode_id_token(id_token).verify!(issuer: options.issuer,
                                          client_id: client_options.identifier,
                                          nonce: stored_nonce)
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(data)
          self.error = data[:error]
          self.error_reason = data[:reason]
          self.error_uri = data[:uri]
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
