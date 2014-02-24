require_relative '../../../test_helper'

class OmniAuth::OpenIDConnect::VersionTest < MiniTest::Test
  def test_version_defined
    refute_nil OmniAuth::OpenIDConnect::VERSION
  end
end
