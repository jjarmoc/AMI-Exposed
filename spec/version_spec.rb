require 'amiexposedversion'

describe AMIEXPOSED::VERSION do

  before(:each) do
  end

  it "version should be 0.0.2" do
    AMIEXPOSED::VERSION.should == "0.0.2"
  end

end