using System;
using System.Collections.Generic;
using Xunit;
using MountSandbox;

namespace MountSandbox.Tests
{
    public class SandboxTests
    {
        [Fact]
        public void TestUnknownEngineThrows()
        {
            Assert.Throws<SandboxException>(() => new Sandbox("invalid_engine"));
        }

        [Fact]
        public void TestDummyEngine()
        {
            using (var sandbox = new Sandbox("dummy"))
            {
                var result = sandbox.Execute(new string[] { "test_command" });
                
                Assert.Equal(0, result.ExitCode);
            }
        }

        [Fact]
        public void TestDummyEngineWithConfig()
        {
            using (var sandbox = new Sandbox("dummy"))
            {
                var mounts = new List<MountInfo>
                {
                    new MountInfo { Dir = "/tmp", ReadOnly = true }
                };

                var envVars = new List<string> { "FOO=BAR" };

                var result = sandbox.Execute(
                    commandArgs: new string[] { "test_command" },
                    mounts: mounts,
                    envVars: envVars,
                    disableNetwork: true,
                    timeoutSecs: 10,
                    maxMemoryMb: 512,
                    maxCpuPercent: 50,
                    dropPrivileges: true,
                    targetUid: 1000,
                    targetGid: 1000,
                    deniedSyscalls: new List<string> { "ptrace" },
                    captureOutput: true
                );

                Assert.Equal(0, result.ExitCode);
            }
        }
        
        [Fact]
        public void TestDockerEngineInit()
        {
            using (var sandbox = new Sandbox("docker"))
            {
                Assert.NotNull(sandbox);
            }
        }
        
        [Fact]
        public void TestPodmanEngineInit()
        {
            using (var sandbox = new Sandbox("podman"))
            {
                Assert.NotNull(sandbox);
            }
        }

        [Fact]
        public void TestGvisorEngineInit()
        {
            using (var sandbox = new Sandbox("gvisor"))
            {
                Assert.NotNull(sandbox);
            }
        }

        [Fact]
        public void TestWasmtimeEngineInit()
        {
            using (var sandbox = new Sandbox("wasmtime"))
            {
                Assert.NotNull(sandbox);
            }
        }

        [Fact]
        public void TestAppContainerEngineInit()
        {
            using (var sandbox = new Sandbox("appcontainer"))
            {
                Assert.NotNull(sandbox);
            }
        }

        [Fact]
        public void TestNativeEngineInit()
        {
            using (var sandbox = new Sandbox("native"))
            {
                Assert.NotNull(sandbox);
            }
        }
    }
}
