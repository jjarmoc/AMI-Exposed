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
     self.name = "SSH Authorized Keys"
     self.description = "Check Authorized Keys for unknown keys"
     self.filename = File.basename(__FILE__, ".rb")
  end
  
  def run
    key_files = instance.runcmd_pty('sudo find / -type f -name "authorized_keys*"')
    unless (key_files.to_s.empty?)
     key_files.to_s.split(/\r?\n/).each { |file|
       unknown_key = instance.runcmd_pty("sudo grep -v #{instance.key_name} #{file}").to_s
       unless (unknown_key == "") 
         create_finding(
          :name => "Unauthorized SSH Key Exists",
          :text => "Found one or more unauthorized SSH keys in the following file;",
          :details => "#{file} contains:\n#{unknown_key}",
          :severity => 3
          )
       end
     }
    end
  end

end