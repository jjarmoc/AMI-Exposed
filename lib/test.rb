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

class BaseTest
  attr_accessor :name, :description, :ami, :instance, :finding, :filename, :config, :verbose
  
  def initialize(instance)
    self.name = "Base Test Module"
    self.description = "This is a base module, meant to be overwritten by intheritence." 
    self.instance = instance
    self.ami = self.instance.image
    self.filename = File.name()
    self.init
    #binding.pry
    self.config = YAML.load(File.read("config/config.yaml"))["tests"][self.filename]
  end

  def create_finding(info)
    defaults = {
      :filename => self.filename,
      :amiId => self.ami.id,
      :instanceId => self.instance.id,
      :text => "",
      :details => "",
      :severity => 0,
    }
    info.merge!(defaults) { |key, v1, v2| v1 }
    finding = Finding.create(info)
    verbose.puts("[T]#{Time.now.ctime} - #{ami.id}(#{instance.id}) \t- Finding: #{finding.to_s}") if verbose
    verbose.puts("[T]#{Time.now.ctime} - #{ami.id}(#{instance.id}) \t- Begin Detail\n#{finding.details}[T]#{Time.now.ctime} - #{ami.id}(#{instance.id}) \t- End Detail ")    
    verbose.flush if verbose
  end
end

module FileHelper  
  def test_file_contents(file)
  file_contents = YAML.load(File.read("config/config.yaml"))["tests"]["file_contents"]
  file_contents.each { |cont_test| 
    output = instance.runcmd_pty('sudo egrep -i "' + cont_test["regex"] + '" ' + file).to_s
    found = (output and not output == "") ? output : false
    
    if (found)
      create_finding(
      :name => "Found #{cont_test["descr"]}",
      :text => "Found #{cont_test["descr"]} in #{file}",
      :details => found,
      :severity => cont_test["sev"]
      )
    end  
  }
  end
  
end