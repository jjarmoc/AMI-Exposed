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

class CreateFindings < ActiveRecord::Migration
  def self.up
    create_table :findings do |t|
      t.integer :id
      t.string :filename
      t.string :name
      t.string :text
      t.string :details
      t.integer :job
      t.string :amiId
      t.string :instanceId
      t.integer :severity
      t.integer :fp
    end

  end

  def self.down
    drop_table :findings
  end
end
