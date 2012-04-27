#AMI Exposed - A framework for security scanning of Amazon Machine Images (AMIs)
#Copyright (C) 2011 Jeff Jarmoc - Dell SecureWorks Counter Threat Unit
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#
# Filters images in a given region and tags all non-windows images.
# Remaining tools use these tags to limit the images under test.

require File.expand_path(File.dirname(__FILE__) + '/config/config')

require 'net/http'
require 'logger'
require "threaded_collections"

puts "++ Starting up..."

AWS.config(:logger => Logger.new(File.expand_path(File.dirname(__FILE__) + '/log/Tag_Images.log')))
instance = key_pair = group = nil

begin
  ec2 = AWS::EC2.new

  # optionally switch to a non-default region
  if region = ARGV.first
    region = ec2.regions[region]
    unless region.exists?
      puts "Requested region '#{region.name}' does not exist.  Valid regions:"
      puts "  " + ec2.regions.map(&:name).join("\n  ")
      exit 1
    end

    # a region acts like the main EC2 interface
    ec2 = region
  end
  
  puts "++ Fetching image list from EC2"
  MyImgs = ec2.images	# Not supplying any filters at this time, the stuff we need doesn't appear filterable currently.
  puts "++ Filtering and tagging #{MyImgs.count} total Images"
  
  tps = ThreadedCollections::ThreadedCollectionProcessor.new(MyImgs)
  tps.process(10) do |thread_id, img|
  # Enumerating the list like this slows us down quite a bit.  Threads help.
  # Expanded SDK filters may allow for future improvements.
    begin
      if (img.type == :machine && img.platform != "windows")
        img.tag('AMI_Exposed', :value => 'Pending')
        puts "++ Thread %.2i: Tagging #{img.id}" %thread_id
      end
    rescue AWS::EC2::Errors::RequestLimitExceeded
       puts "!! Thread %.2i: Rate Limit exceeded, sleeping for 30 seconds." %thread_id
       sleep(60)
       retry
    end
  end
  puts "++ Tagged #{ec2.images.tagged("AMI_Exposed").tagged_values("Pending").count} images."
end