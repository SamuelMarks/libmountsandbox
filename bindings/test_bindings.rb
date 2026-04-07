require_relative 'sandbox'
require 'rbconfig'

def main
  puts "Testing Ruby FFI Bindings..."
  
  lib_name = case RbConfig::CONFIG['host_os']
             when /darwin/ then 'libmountsandbox.dylib'
             when /mswin|msys|mingw|cygwin|bccwin|wince|emc/ then 'mountsandbox.dll'
             else 'libmountsandbox.so'
             end
  
  # Resolve relative to current file
  lib_path = File.join(File.dirname(__FILE__), "..", "build", lib_name)
  
  # Try to execute ls
  sandbox = LibMountSandbox::SandboxWrapper.new(lib_path)
  
  status = sandbox.execute("dummy", ["echo", "hello"])
  puts "Command returned status: #{status}"
end

if __FILE__ == $0
  main
end
