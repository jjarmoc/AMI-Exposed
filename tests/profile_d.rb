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
include FileHelper  

 def init
   self.name = "Profile_d Checks"
   self.description = "Checks data within files under /etc/profile.d"
   self.filename = File.basename(__FILE__, ".rb")
 end
 
 def run
   files = instance.runcmd_pty('sudo find /etc/profile.d -type f')
   unless (files.to_s.empty?)  
       unless (files.to_s =~ /No such/)
	  files.to_s.split(/[\r\n]+/).each { |file|
          test_file_contents(file)
          }
       end
   end    
 end
 
end
