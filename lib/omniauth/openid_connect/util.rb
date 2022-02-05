# -*- coding:utf-8 -*-

module OmniAuth
  module OpenIDConnect

    # @param [String or Hash] key_or_hash  PEM形式の証明書データ
    # @raise [OpenSSL::X509::CertificateError] 証明書のフォーマットが不正
    def self.parse_x509_key key_or_hash, kid
      raise TypeError if !key_or_hash.is_a?(String) && !key_or_hash.is_a?(Hash)
      
      if key_or_hash.is_a?(Hash)
        # https://www.googleapis.com/oauth2/v1/certs format
        raise TypeError if !kid
        key_or_hash.each do |key, pem|
          if key == kid
            return OpenSSL::X509::Certificate.new(pem).public_key
          end
        end
        raise ArgumentError, "missing kid: #{kid}"
      else
        return OpenSSL::X509::Certificate.new(key_or_hash).public_key
      end
    end


    # Decode JSON Web Key (JWK) or JWK Set format.
    # See RFC 7517
    # @param [String or Hash] key_or_hash JSON形式の文字列, またはハッシュ.
    #        Sample: https://www.googleapis.com/oauth2/v3/certs
    def self.parse_jwk_key key_or_hash, kid
      if key_or_hash.is_a?(String)
        json = JSON.parse(key_or_hash)
      elsif key_or_hash.is_a?(Hash)
        json = key_or_hash
      else
        raise TypeError, "key was #{key_or_hash.class}, #{key_or_hash.inspect}"
      end

      if json.has_key?('keys')
        return JSON::JWK::Set.new json['keys']
      else
        return JSON::JWK.new json
      end
    end

  end # module OpenIDConnect
end
