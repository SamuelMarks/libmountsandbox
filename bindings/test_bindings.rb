require_relative 'sandbox'

def main
  puts "Testing Ruby FFI Bindings..."
  
  # Resolve relative to current file
  lib_path = File.join(File.dirname(__FILE__), "..", "build", (RUBY_PLATFORM =~ /darwin/ ? "libmountsandbox.dylib" : "libmountsandbox.so"))
  
  # Try to execute ls
  sandbox = LibMountSandbox::SandboxWrapper.new(lib_path)
  
  status = sandbox.execute("dummy", ["echo", "hello"])
  puts "Command returned status: #{status}"
end

if __FILE__ == $0
  main
end
