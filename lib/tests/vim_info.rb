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
   self.name = "Vim Info checks"
   self.description = "Checks for existence of .viminfo file(s), and data within."
   self.filename = File.basename(__FILE__, ".rb")
 end
 
 def run
   files = instance.runcmd_pty('sudo find / -type f -name ".vim_info"')
   unless (files.to_s.empty?)
    create_finding(
    :name => "Vim info file(s) exist",
    :text => "Found one or more .vim_info files",
    :details => files.to_s,
    :severity => 1
    )
    
    files.to_s.split(/[\r\n]+/).each { |file|
      test_file_contents(file)
      }
   end    
 end
 
end
