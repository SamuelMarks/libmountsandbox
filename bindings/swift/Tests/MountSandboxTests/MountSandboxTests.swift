import XCTest
@testable import MountSandbox

final class MountSandboxTests: XCTestCase {
    
    func testExecuteDummyEngine() throws {
        let sandbox = LibMountSandbox()
        let status = try sandbox.execute(engineName: "dummy", commandArgs: ["echo", "hello swift"])
        // The dummy engine always returns 0
        XCTAssertEqual(status, 0)
    }
    
    func testExecuteUnknownEngine() {
        let sandbox = LibMountSandbox()
        XCTAssertThrowsError(try sandbox.execute(engineName: "unknown_engine_test", commandArgs: ["echo", "hello"])) { error in
            guard let sandboxError = error as? LibMountSandbox.SandboxError else {
                XCTFail("Expected SandboxError")
                return
            }
            if case let .invalidEngine(name) = sandboxError {
                XCTAssertEqual(name, "unknown_engine_test")
            } else {
                XCTFail("Expected invalidEngine error")
            }
        }
    }
    
    func testExecuteWithConfig() throws {
        let sandbox = LibMountSandbox()
        let config = SandboxConfig(
            mounts: [SandboxMount(dir: "/tmp", readOnly: true)],
            disableNetwork: true,
            envVars: ["TEST=1"],
            timeoutSecs: 10,
            maxMemoryMb: 512,
            maxCpuPercent: 50,
            dropPrivileges: true,
            targetUid: 1000,
            targetGid: 1000,
            deniedSyscalls: ["ptrace"]
        )
        
        let status = try sandbox.execute(engineName: "dummy", commandArgs: ["test"], config: config)
        XCTAssertEqual(status, 0)
    }
}
