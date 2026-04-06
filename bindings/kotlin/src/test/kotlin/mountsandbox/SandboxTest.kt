package mountsandbox

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SandboxTest {
    @Test
    fun testExecute() {
        val sandbox = Sandbox()
        val config = SandboxConfig()
        // No need to populate all pointers for dummy test since it just returns 0
        config.disable_network = 1
        config.timeout_secs = 5
        config.max_memory_mb = 128
        config.max_cpu_percent = 100
        config.drop_privileges = 1
        config.target_uid = 1000
        config.target_gid = 1000

        val status = sandbox.execute("dummy", listOf("ls", "-la"), config)
        assertEquals(0, status)
    }

    @Test
    fun testExecuteUnknownEngine() {
        val sandbox = Sandbox()
        assertFailsWith<IllegalArgumentException> {
            sandbox.execute("nonexistent_engine", listOf("ls"))
        }
    }

    @Test
    fun testExecuteNilConfig() {
        val sandbox = Sandbox()
        val status = sandbox.execute("dummy", listOf("echo", "hello"))
        assertEquals(0, status)
    }
}
