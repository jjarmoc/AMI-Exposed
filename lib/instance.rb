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

gem 'net-ssh', '~> 2.1.4'
require 'net/ssh'

module AWS
  class EC2
    class Instance < Resource
      attr_accessor :key_path
      attr_accessor :verbose
      
      def sshUser
        return self.tags['sshUser'] if self.tags['sshUser']
        self.image.tags['sshUser']
      end
      
      def sshUser=(value)
        self.tag('sshUser', :value => value)
        self.image.tag('sshUser', :value => value)
      end
      
      def user_gets_shell?(user)
        #This is a lame way to make sure our user gets a shell and not just a banner.
          test = ""
          test = runcmd("echo 'TEST'", user)
	ret = test =~ /TEST/ ? true : false 
	  return ret
      end
      
      def parse_user_from_banner
        #In cases where a root login tells us what account to use, we parse that.
        #
        verbose.puts("[i]#{Time.now.ctime} - #{image.id}(#{self.id}) - Parsing username from root banner.") if verbose
        banner = runcmd("echo 'TEST'", "root")
        ssh_conf = YAML.load(File.read("config/config.yaml"))["ssh"]
        ssh_conf["regex"].each{ |rhash| 
          match = Regexp.new(rhash["regex"], true).match banner
          if match
            verbose.puts("[i]#{Time.now.ctime} - #{image.id}(#{self.id}) - Parsed #{match[rhash["capturegroup"]]} from banner.") if verbose
            return match[rhash["capturegroup"]] if user_gets_shell?(match[rhash["capturegroup"]])
          end
         }
         
         verbose.puts("[i]#{Time.now.ctime} - #{image.id}(#{self.id}) Couldn't parse SSH Banner: #{runcmd("test", "root")}") if verbose
         return nil
      end
       
       
       
      def brute_user()
        #Attempts to dictionary attack a username from a list of users defined in config.
        #Returns the username on success, otherwise returns false.
		#
		#Name is a little off, since it's not a true bruteforce.
        verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) Iterating Dictionary of users..." if verbose
        ssh_conf = YAML.load(File.read("config/config.yaml"))["ssh"]
        ssh_conf["userlist"].each{ |user|
          begin
            return user if user_gets_shell?(user)
          rescue Net::SSH::AuthenticationFailed => e 
            verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) ! #{user} : #{e.message}" if verbose
            #We expect this if it's an invalid user.
            next
          end
        }
        return nil
      end
       
      def get_user
           return sshUser if sshUser
           verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) - Attempting to get SSH username" if verbose
           self.sshUser = "root" if user_gets_shell?("root")
           self.sshUser = parse_user_from_banner unless self.sshUser
           self.sshUser = brute_user() unless self.sshUser
           verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) - Got SSH username #{sshUser}" if verbose
           return sshUser
       end
      
      def runcmd(cmd, user=sshUser)
        begin
          unless (status == :running)
            # TODO This needs some cleanup, but we should ideally check an instance for running state before trying to run commands.
            puts "Non-Running Instance"
            return
          end
          unless (user)
            user = get_user()
          end
          unless (key_path)
            ssh_conf = YAML.load(File.read("config/config.yaml"))["ssh"]
            key_path = ssh_conf["key_path"]        
          end
          
          if (user != sshUser && sshUser)
            user = sshUser
          end
        
          #Kind of pointless to start a new session for each command, but for now this works.
          Net::SSH.start( dns_name, user, :port => 22, :keys => "#{key_path}#{key_name}.pem") { |ssh|
         return ssh.exec!(cmd)
         }
        rescue Net::SSH::HostKeyMismatch => e
            verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) adding new key: #{e.fingerprint}" if verbose
            e.remember_host!
            retry
        rescue => e
            # Probably just can't connect yet.  Sleep for a while and try again.
            # This needs to be fleshed out, or we can get stuck here forever...
			# Timeouts in outer loops catch that condition for now.
            verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) ! Can't SSH to #{dns_name} Sleeping 30 seconds." if verbose
            verbose.flush if verbose
            sleep(30)          
              if (status == :running)  
                retry
              else
                verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) ! ERROR: Instance changed status to #{status} unexpectedly." if verbose
                puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) ! ERROR: Instance changed status to #{status} unexpectedly."
                image.test_status="Failed"
                return
              end
        end  
      end
      
      def runcmd_pty(cmds, user=sshUser)
         collect = []
         
         unless (key_path)
           ssh_conf = YAML.load(File.read("config/config.yaml"))["ssh"]
           key_path = ssh_conf["key_path"]        
         end
         
         unless (user)
           user = self.get_user()
         end
         
       begin
         Net::SSH.start( dns_name, user, :port => 22, :keys => "#{key_path}#{key_name}.pem") do |session|
             cmds.each_with_index do |cmd, index|
               collect[index] = ""
               session.open_channel do |channel|

               channel.request_pty do |ch, success|
                 raise "Error requesting pty" unless success
                 ch.exec(cmd) do |ch, success|
                 raise "Error opening shell" unless success
                 end
               end

               channel.on_extended_data do |ch, type, data|
                 STDOUT.print "Error: #{data}\n"
               end

               channel.send_data "#{cmd}\nexit\n"

               channel.on_data do |ch, data|
                 data.slice!("#{cmd}\r\nexit\r\n")
                 collect[index] << data
               end

               session.loop
             end
           end
         end     
         
          #Edge case for sure, but some boxes don't allow sudo, and I'm sudoing most commands throughout.
          if (collect.to_s =~ /sudo\: command not found/i)
             cmds.slice!(/^sudo/)
             collect = runcmd_pty(cmds) #rerun modified command.
          end
                              
         return collect.to_s.gsub(/\r\n.+Permission denied\r\n/i, "\r\n") #Messy, raising an exception may be better.
         
       rescue Net::SSH::HostKeyMismatch => e
           verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) ! Adding new SSH key: #{e.fingerprint}" if verbose
           e.remember_host!
           retry       
       rescue => e
         verbose.puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) ! Can't SSH to #{dns_name} Sleeping 10 seconds."
         verbose.flush if verbose
         sleep(10)
         retry
       end 
      
      end
     
       def run_test(test)
         begin
         timeout(600) { #allow up to 10min for any individual test.
           load test
           current_test = Test.new(self)
           current_test.verbose = verbose if verbose
           verbose.puts("[i]#{Time.now.ctime} - #{image.id}(#{id}) - Running #{current_test.name}") if verbose
           current_test.run
           verbose.puts("[i]#{Time.now.ctime} - #{image.id}(#{id}) - Completed #{current_test.name}") if verbose
           verbose.flush if verbose
          }
        rescue Timeout::Error => e
            verbose.puts("[I]#{Time.now.ctime} - #{image.id}(#{id}) ! ERROR: Test #{Test.name} timed out.")
            return
        end
       end
       
       def run_tests()
         puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) - Running all tests.\n"
         tests = Dir.glob("tests/*.rb")
         tests.each{ |test|
            self.run_test(test)
            }  
        puts "[i]#{Time.now.ctime} - #{image.id}(#{id}) - Completed all tests.\n"
       end
       
    end
  end
end
