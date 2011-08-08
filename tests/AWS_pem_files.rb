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
   self.name = "AWS x.509 checks"
   self.description = "Checks for presence of AWS x.509 file(s)"
   self.filename = File.basename(__FILE__, ".rb")
 end
 
 def run
   files = instance.runcmd_pty('sudo find / -regextype posix-awk -regex ".*cert-[A-Z0-9]{32}\.pem" -type f')
   unless (files.to_s.empty?)
    create_finding(
    :name => "AWS Certificate File(s) Exist",
    :text => "Found one or more AWS .pem certificate files",
    :details => files.to_s,
    :severity => 2
    )
   end
    
   files = instance.runcmd_pty('sudo find / -regextype posix-awk -regex ".*pk-[A-Z0-9]{32}\.pem" -type f')
   unless (files.to_s.empty?)
    create_finding(
     :name => "AWS Key File(s) Exist",
     :text => "Found one or more AWS .pem private key files",
     :details => files.to_s,
     :severity => 3
     )
   end
 end
end
