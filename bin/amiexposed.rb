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

banner = <<eos
       d8888 888b     d888 8888888      8888888888                                                   888 
      d88888 8888b   d8888   888        888                                                          888 
     d88P888 88888b.d88888   888        888                                                          888 
    d88P 888 888Y88888P888   888        8888888    888  888 88888b.   .d88b.  .d8888b   .d88b.   .d88888 
   d88P  888 888 Y888P 888   888        888        `Y8bd8P' 888 "88b d88""88b 88K      d8P  Y8b d88" 888 
  d88P   888 888  Y8P  888   888        888          X88K   888  888 888  888 "Y8888b. 88888888 888  888 
 d8888888888 888   "   888   888        888        .d8""8b. 888 d88P Y88..88P      X88 Y8b.     Y88b 888 
d88P     888 888       888 8888888      8888888888 888  888 88888P"   "Y88P"   88888P'  "Y8888   "Y88888 
                                                            888                                          
                                                            888                                          
                                                            888                                          
eos

puts banner
puts "++ Starting up..."
require 'config/config'
require "threaded_collections"

#require File.expand_path(File.dirname(__FILE__) + '/lib/threaded_collections/threaded_collections')
#require File.expand_path(File.dirname(__FILE__) + '/config/config')

orig_stdout = $stdout
THREADS=13 # Feel free to adjust this

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
end

begin
puts "++ Started."

logconf = YAML.load(File.read("config/config.yaml"))["logs"]
if (logconf["console"] && logconf["console"] != "STDOUT")
  puts "Redirecting stdout to #{logconf["console"]}"
  $stdout = File.open(logconf["console"], 'a')
  $stdout.sync = true
end
puts "++ Verbose logs in: #{logconf["verbosepath"]}" if logconf["verbosepath"]

puts "Getting images"
#If you want to modify how you find in-scope images, this is the place.
begin
  # MyImgs = ec2.images.tagged("AMI_Exposed").tagged_values('Pending')
  MyImgs = ec2.images.tagged("amiexposed").tagged_values('yes')
rescue 
  puts "Error .."
end

total = MyImgs.count

completed = 0
starttime = Time.now
puts "++ Starting test of #{MyImgs.count} AMIs with #{THREADS} threads at #{starttime.ctime}"

tps = ThreadedCollections::ThreadedCollectionProcessor.new(MyImgs)
tps.process(THREADS) do |thread_id, myimg|
  begin
    timeout(2400) {   #Allow 40 minutes for a test thread to complete
      puts "#{Time.now.ctime} ++ #{completed}/#{total} - Thread %.2i: Scanning #{myimg.id}" %thread_id
      myimg.verbose = File.open(logconf["verbosepath"] + myimg.id + ".log", 'a+') if logconf["verbosepath"]
      myimg.test
    }
  rescue AWS::EC2::Errors::RequestLimitExceeded
     puts "!! Thread %.2i: Rate Limit exceeded, sleeping for 30 seconds." %thread_id
     sleep(30)
     retry
  rescue Timeout::Error => e
     myimg.verbose.puts("S#{Time.now.ctime} - #{id} ! ERROR: Test exceeded 40 minutes, halting test.") if myimg.verbose
     puts("S#{Time.now.ctime} - #{id} ! ERROR: Test exceeded 40 minutes, halting test.")
     myimg.tag('AMI_Exposed', :value => "Failed")
     myimg.tag('Fail', :value => "40 Minute timeout while testing: #{e.message}")
     # TODO: Get Console log and stuff it in verbose.
	 # Turns out getting console log isn't supported through the SDK, and hitting the API directly would be a hassle.
     next
  rescue => e
     myimg.verbose.puts("S#{Time.now.ctime} - #{myimg.id} ! ERROR: Unhandled exception reached outer handler, aborting.") if myimg.verbose
     myimg.verbose.puts("S#{Time.now.ctime} - #{myimg.id} ! ERROR: Unhandled exception backtrace: #{e.backtrace.join("\n")}") if myimg.verbose
     myimg.tag('AMI_Exposed', :value => "Failed")
     myimg.tag('Fail', :value => "Unhandled Exception: #{e.message}")
     next  
  ensure
       # clean up
       completed+=1
       puts "#{Time.now.ctime} ++ #{completed}/#{total} - Thread %.2i: Completed #{myimg.id}" %thread_id
       myimg.verbose.flush if myimg.verbose
       myimg.testinst.terminate if myimg.testinst
  end
end

difference = Time.now - starttime
seconds    =  difference % 60
difference = (difference - seconds) / 60
minutes    =  difference % 60
difference = (difference - minutes) / 60
hours      =  difference % 24
difference = (difference - hours)   / 24
days       =  difference % 7
 
puts "++ Completed #{completed} AMIs in #{days} days, #{hours}:#{minutes}:#{seconds}"
end
