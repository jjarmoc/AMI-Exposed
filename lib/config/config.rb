# Copyright 2011 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# Modified for use with AMI_Exposed
#
require 'rubygems'
require 'aws'
require 'logger'
require "threaded_collections"
require 'active_record'

require "timeout"
require "./lib/Instance.rb"
require "./lib/Image.rb"
require "./lib/test.rb"
require "./lib/finding.rb"


config_file = File.join(File.dirname(__FILE__),
                        "config.yaml")
unless File.exist?(config_file)
  puts <<END
To run, put your credentials in config.yml as follows:

ec2:
access_key_id: YOUR_ACCESS_KEY_ID
secret_access_key: YOUR_SECRET_ACCESS_KEY

END
  exit 1
end

config = YAML.load(File.read(config_file))

unless config["ec2"].kind_of?(Hash)
  puts <<END
config.yml is formatted incorrectly.  Please use the following format:

ec2:
  access_key_id: YOUR_ACCESS_KEY_ID
  secret_access_key: YOUR_SECRET_ACCESS_KEY

END
  exit 1
end

AWS.config(config["ec2"])
AWS.config(:logger => Logger.new(File.expand_path(File.dirname(__FILE__) + '/../log/AWS.log')))
dbconfig = YAML::load(File.open(File.join(File.dirname(__FILE__) + '/database.yaml')))
ActiveRecord::Base.establish_connection(dbconfig)



