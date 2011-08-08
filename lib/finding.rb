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

class Finding < ActiveRecord::Base
  after_initialize :afterinit
  
  SEVERITY = ["None", "Low", "Medium", "High"]
  
  def afterinit 
      self.text = "" unless text
      self.detail = "" unless text
      self.save!
  end
  
  def to_s
    return "Finding: #{filename}/#{name}: found sev:#{self.severity_as_s} finding."
  end
  
  def severity_as_s
    SEVERITY[self.severity]
  end
  
end