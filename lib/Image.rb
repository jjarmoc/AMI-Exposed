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

module AWS
  class EC2
    class Image < Resource
      attr_accessor :key_path, :verbose, :testinst
      @@archtomachine ={ :i386 => "m1.small",
                         :x86_64 => "m1.large"}
      
      def sshUser
        self.tags['sshUser']
      end

      def sshUser=(value)
        self.tag('sshUser', :value => value)
      end
       
      def test_status
        self.tags['AMI_Exposed']
      end

      def test_status=(value)
        self.tag('AMI_Exposed', :value => value)
        self.testinst.tag('AMI_Exposed', :value => value) if self.testinst
      end
      
      def test
        
        self.test_status = "Preparing"
        verbose.puts("[I]#{Time.now.ctime} - #{id} - Preparing to Test") if verbose
        
        key_name = YAML.load(File.read("config/config.yaml"))["ssh"]["key_name"]        
      begin
       timeout(900) {
          #If we don't return a started instance in 15 mins, timeout.
         verbose.puts("[I]#{Time.now.ctime} - #{id} - Launching instance") if verbose
         self.testinst = self.run_instance(:key_name => key_name, 
         :instance_type => @@archtomachine[architecture])
         sleep(5) #give it a couple seconds; sometimes the API won't update immediately.
         self.testinst.verbose = verbose
         # !!! This shouldn't be necessary, but keeps from dieing at ##HERE when status is nil
         self.testinst.status == :pending
         #
       }
      rescue AWS::EC2::Errors::AuthFailure => e
         verbose.puts("[I]#{Time.now.ctime} - #{id} - Paid image, skipping") if verbose
         self.tag('AMI_Exposed', :value => "Paid")
         self.tag('Paid', :value => e.message)
         return 
      rescue Timeout::Error => e
         verbose.puts("[I]#{Time.now.ctime} - #{id} ! ERROR: Timeout waiting for instance to start: #{e.message}") if verbose
         self.tag('AMI_Exposed', :value => "Failed")
         self.tag('Fail', :value => "Timeout waiting for instance to start: #{e.message}")
         # TODO: Get Console log and stuff it in verbose.
         return
      rescue => e
         verbose.puts("[I]#{Time.now.ctime} - #{id} ! ERROR: #{e.message}") if verbose
         self.tag('AMI_Exposed', :value => "Failed")
         self.tag('Fail', :value => e.message) 
         return         
      end  
     
     
        
      unless (testinst && testinst.status)
         verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) ! ERROR: Instance failed to spawn.") if verbose
         return
      end
        
      sleep 1 until (testinst.status != :pending) ##HERE
      verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) - Launched instance, status: #{testinst.status}") if verbose
        
      unless (testinst.status == :running)
        verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) !ERROR: Launched instance in bad status: #{testinst.status}") if verbose
        puts "#{id}(#{testinst.id}) !ERROR: Launched instance in bad status: #{testinst.status}\n"
        return  
      end
        
      begin
        timeout(1800) {  #If we don't get a username in 30 mins, timeout.
          if testinst.get_user
            verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) - Discovered SSH Username: #{testinst.sshUser}") if verbose
          else
            verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) !ERROR: Failed to discover user.")
            puts "#{id}(#{testinst.id}) !ERROR: Failed to discover user."
            return
          end
        }
      rescue Timeout::Error => e
        verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) ! ERROR: Timeout while getting user: #{e.message}") if verbose
        self.tag('AMI_Exposed', :value => "Failed")
        self.tag('Fail', :value => "Timeout while getting user: #{e.message}")
        return
      end
        
      begin
      timeout(2400) {  #If we don't complete tests in 40 mins, timeout.
          self.test_status = "In Progress"
          self.testinst.run_tests
        
          self.test_status = "Completed"
          verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) - Test Status: Completed") if verbose
          verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) - Instance Status: #{testinst.status}") if verbose
          verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) - Terminating instance.") if verbose
          self.testinst.terminate
          sleep 1 until testinst.status != :running
          verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) - Instance Status: #{testinst.status}") if verbose
        }
      rescue Timeout::Error => e
          verbose.puts("[I]#{Time.now.ctime} - #{id}(#{testinst.id}) ! ERROR: Timeout waiting for instance to test: #{e.message}") if verbose
          self.tag('AMI_Exposed', :value => "Failed")
          self.tag('Fail', :value => "Timeout waiting for instance to test: #{e.message}")
          return
      end
        
        
      ensure
          # clean up
          [self.testinst].compact.each(&:delete)      
      end
       
       
    end
  end
end
