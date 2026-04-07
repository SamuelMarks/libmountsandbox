require 'minitest/autorun'
require 'rbconfig'
require_relative 'sandbox'

class TestRubyBindings < Minitest::Test
  def setup
    lib_name = case RbConfig::CONFIG['host_os']
               when /darwin/ then 'libmountsandbox.dylib'
               when /mswin|msys|mingw|cygwin|bccwin|wince|emc/ then 'mountsandbox.dll'
               else 'libmountsandbox.so'
               end
    @lib_path = File.join(File.dirname(__FILE__), "..", "build", lib_name)
    @sandbox = LibMountSandbox::SandboxWrapper.new(nil)
  end

  def test_resolve_lib_path
    assert_kind_of String, LibMountSandbox.resolve_lib_path
    assert_equal "custom.so", LibMountSandbox.resolve_lib_path("custom.so")
  end

  def test_dummy_engine_execution
    # Test simple execution with dummy engine
    status = @sandbox.execute("dummy", ["echo", "hello"])
    assert_equal 0, status
  end

  def test_dummy_engine_execution_with_config
    # Test execution with config
    config = LibMountSandbox::SandboxConfig.new
    config.pointer.clear
    config[:timeout_secs] = 5

    status = @sandbox.execute("dummy", ["echo", "hello"], config)
    assert_equal 0, status
  end

  def test_unknown_engine
    assert_raises(ArgumentError) do
      @sandbox.execute("unknown_engine_xyz", ["ls"])
    end
  end

  def test_invalid_lib_path
    assert_raises(LoadError) do
      LibMountSandbox::SandboxWrapper.new("/nonexistent/path/to/lib.so")
    end
  end
end
