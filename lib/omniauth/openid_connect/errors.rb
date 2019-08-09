# frozen_string_literal: true

module OmniAuth
  module OpenIDConnect
    class Error < RuntimeError; end
    class MissingCodeError < Error; end
    class MissingIdTokenError < Error; end
  end
end
