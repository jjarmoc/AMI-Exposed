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

class Test < BaseTest

 def init
   self.name = "Active Connection Checks"
   self.description = "Checks for presence of active connections that may be persistent backdoors."
   self.filename = File.basename(__FILE__, ".rb")
 end
 
 def run
 allowed_ips = YAML.load(File.read("config/config.yaml"))["tests"]["active_connections"]["ignore_host_connections"]
 verbose.puts("[T]#{Time.now.ctime} - #{ami.id}(#{instance.id}) - Ignoring connections from: #{allowed_ips.join(", ")}") if verbose
 output = instance.runcmd_pty('sudo netstat -n --inet -p | grep -v "Internet connections" | grep -v "Proto"')
 lines = output.split(/[\r\n]+/)
 lines.each {|line|
   match = /^\s?(tcp|udp)\s+[0-9]+\s+[0-9]+\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})\s+[A-Z_]+\s?([0-9]{1,5})\/(.*)/.match line
    if match     
         remoteip = match[4]
      if (allowed_ips.find_all{|ip| ip == remoteip}.empty?)
        localip = match[2]
	break if remoteip = localip
	proto = match[1]
	locaport = match[3]
        remoteport = match[5]
        pid = match[6]
        procinfo = match[7]
        
        procdetail = instance.runcmd_pty("sudo ps -p #{pid} | grep -v PID")
        
        create_finding(
          :name => "Active Connection Discovered",
          :text => "Found an active #{proto} connection to #{remoteip}:#{remoteport} from #{pid}/#{procinfo}, potentially a persistent backdoor.",
          :details => "PID: #{pid}/#{procinfo} communicating with #{remoteip}\r\n#{line}\r\n#{procdetail}",
          :severity => 3
          )
      end
    end
 }
 end
end
