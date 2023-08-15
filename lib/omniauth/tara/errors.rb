# frozen_string_literal: true

module OmniAuth
  module Tara
    class Error < RuntimeError; end

    class MissingCodeError < Error; end

    class MissingIdTokenError < Error; end
  end
end
