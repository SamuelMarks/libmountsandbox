import os
from sandbox import LibMountSandbox

def main():
    print("Testing Python FFI Bindings...")
    
    # Resolve relative to current file
    lib_path = os.path.join(os.path.dirname(__file__), "..", "build", f"libmountsandbox.{'dylib' if os.uname().sysname == 'Darwin' else 'so'}")
    sandbox = LibMountSandbox(lib_path=lib_path)
    
    status = sandbox.execute("native", ["ls", "-la"])
    print(f"Command returned status: {status}")

if __name__ == "__main__":
    main()
