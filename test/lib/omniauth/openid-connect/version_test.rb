require_relative '../../../test_helper'

describe OmniAuth::OpenIDConnect::VERSION do
  it "must be defined" do
    OmniAuth::OpenIDConnect::VERSION.wont_be_nil
  end
end
