# frozen_string_literal: true

module OmniAuth
  module OpenIDConnect
    module Util
      # @param [String or Hash] key_or_hash  Certificate data in PEM format
      # @raise [OpenSSL::X509::CertificateError] Certificate format is incorrect
      def self.parse_x509_key(key_or_hash, kid)
        raise TypeError if !key_or_hash.is_a?(String) && !key_or_hash.is_a?(Hash)

        if key_or_hash.is_a?(Hash)
          # https://www.googleapis.com/oauth2/v1/certs format
          raise TypeError unless kid

          key_or_hash.each do |key, pem|
            return OpenSSL::X509::Certificate.new(pem).public_key if key == kid
          end
          raise ArgumentError, "missing kid: #{kid}"
        else
          OpenSSL::X509::Certificate.new(key_or_hash).public_key
        end
      end

      # Decode JSON Web Key (JWK) or JWK Set format.
      # See RFC 7517
      # @param [String or Hash] key_or_hash   JSON-formatted string, or a hash.
      #        Sample: https://www.googleapis.com/oauth2/v3/certs
      def self.parse_jwk_key(key_or_hash, _kid)
        case key_or_hash
        when String
          json = JSON.parse(key_or_hash)
        when Hash
          json = key_or_hash
        else
          raise TypeError, "key was #{key_or_hash.class}, #{key_or_hash.inspect}"
        end

        if json.key?('keys')
          JSON::JWK::Set.new json['keys']
        else
          JSON::JWK.new json
        end
      end
    end
  end
end
