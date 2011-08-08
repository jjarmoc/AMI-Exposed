require 'rubygems'
#gem 'mysql2', '< 0.3'
#require '/var/lib/gems/1.8/gems/mysql2-0.2.11'
require 'active_record'
require 'yaml'
require 'config/config.rb'
 
task :default => :migrate
desc "Migrate the database through scripts in db/migrate. Target specific version with VERSION=x"

task :migrate => :environment do
  ActiveRecord::Migrator.migrate('db/migrate', ENV["VERSION"] ? ENV["VERSION"].to_i : nil )
end
 
task :environment do
  ActiveRecord::Base.establish_connection(YAML::load(File.open('config/database.yaml')))
  ActiveRecord::Base.logger = Logger.new(File.open('log/database.log', 'a'))
end
