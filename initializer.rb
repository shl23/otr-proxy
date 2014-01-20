require "celluloid"
require "celluloid/io"
require "nokogiri"
require "securerandom"
require "fileutils"
require "yaml"
require "digest/sha2"

require "otr4j-bc147.jar"

Dir["./proxy/**.rb"].each do |file|
  require file
end

Celluloid.exception_handler do |ex|
  puts "#{ex.class}: #{ex.message}"
  puts ex.backtrace
end

proxy = ProxyServer.new

puts "* Accepting connections"

while true do
  sleep 60
end