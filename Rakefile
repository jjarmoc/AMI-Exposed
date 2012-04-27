require 'rubygems'
#gem 'mysql2', '< 0.3'
#require '/var/lib/gems/1.8/gems/mysql2-0.2.11'
require 'rake'
require 'rdoc/task'
require 'rubygems/package_task'
require 'rspec/core'
require 'rspec/core/rake_task'
require './lib/amiexposedversion'
$:.unshift  File.join(File.dirname(__FILE__), "lib")

task :default => :spec

desc "Run all specs in spec directory"
RSpec::Core::RakeTask.new(:spec)

desc 'Generate documentation for AMIEXPOSED.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'AMIEXPOSED'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README.rdoc')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

spec = Gem::Specification.new do |s|
  s.name = %q{amiexposed}
  s.version = AMIEXPOSED::VERSION
  s.authors = ["Jeff Jarmoc"]
  s.date = %q{2012-04-27}
  s.email = %q{mkonda@jemurai.com}
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = true
  s.extra_rdoc_files = [ "LICENSE.txt", "README.rdoc" ]
  s.files = Dir["**/*"] - Dir["*.gem"]
  s.rdoc_options = ["--charset=UTF-8"]
  s.files = FileList["{bin,lib}/**/*"].to_a
  s.require_paths = ["lib"]
  s.summary = %q{Ruby based tool to check AMI instances for potential issues.}
  # s.add_dependency("dependency", ">= 0.x.x")
end
 
desc "Build gem file"
Gem::PackageTask.new(spec) do |pkg| 
  pkg.need_tar = true 
  pkg.need_zip = true
end

#require 'active_record'
#require 'yaml'
#require 'config/config.rb'
#task :default => :migrate
#desc "Migrate the database through scripts in db/migrate. Target specific version with VERSION=x"

#task :migrate => :environment do
#  ActiveRecord::Migrator.migrate('db/migrate', ENV["VERSION"] ? ENV["VERSION"].to_i : nil )
#end
 
#task :environment do
#  ActiveRecord::Base.establish_connection(YAML::load(File.open('config/database.yaml')))
#  ActiveRecord::Base.logger = Logger.new(File.open('log/database.log', 'a'))
#end
