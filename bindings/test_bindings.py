import os
import sys
from sandbox import LibMountSandbox

def main():
    print("Testing Python FFI Bindings...")
    
    if sys.platform == 'darwin':
        lib_name = 'libmountsandbox.dylib'
    elif sys.platform == 'win32' or sys.platform == 'cygwin':
        lib_name = 'mountsandbox.dll'
    else:
        lib_name = 'libmountsandbox.so'

    # Resolve relative to current file
    lib_path = os.path.join(os.path.dirname(__file__), "..", "build", lib_name)
    sandbox = LibMountSandbox(lib_path=lib_path)
    
    status = sandbox.execute("dummy", ["ls", "-la"])
    print(f"Command returned status: {status}")

if __name__ == "__main__":
    main()
