// A sketch of Lantern for Kotlin (Android), over the C API through JNI
// (../c/lantern_jni.c): an example, not a package. It shows the shape a
// binding takes: the app's HTTP stack (OkHttp, HttpURLConnection) as the
// transport, a client that is closed, errors as exceptions. The rest of the
// API follows the same pattern, one native function per C call.
package dev.boreale.lantern

/** What the server answered: its status, its header lines as name, value, name, value…, its body. */
class HttpResponse(val status: Int, val headers: Array<String>, val body: ByteArray)

/**
 * The app's HTTP stack. Called on the thread that called the client, which
 * waits for it: call the client off the main thread. It does TLS (and pins
 * the server's key, SPEC.md 5.3), follows no redirect, adds no header but
 * Host and the body's framing. A connection that failed: throw, and the
 * call fails with LANTERN_ERROR_TRANSPORT.
 */
fun interface Transport {
    fun send(method: String, url: String, headers: Array<String>, body: ByteArray): HttpResponse
}

/** A lantern_error: its status (LANTERN_ERROR_*), the HTTP status and § 12's code when the server sent one. */
class LanternException(val status: Int, val httpStatus: Int, val code: String, message: String) : Exception(message)

/** What the handshake says of the server. */
data class Server(val uid: String, val name: String, val base: String)

/** A lantern_client: one thread at a time; close it when done. */
class Client(origin: String, userAgent: String, platform: String?, transport: Transport) : AutoCloseable {
    private var handle: Long = Native.clientCreate(origin, userAgent, platform, transport)

    /** GET /.well-known/lantern; null for a handshake of a newer schema (SPEC.md 3.2). */
    fun handshake(): Server? {
        check(handle != 0L) { "closed" }
        val fields = Native.clientHandshake(handle) ?: return null
        return Server(fields[0], fields[1], fields[2])
    }

    override fun close() {
        if (handle != 0L) {
            Native.clientFree(handle)
            handle = 0L
        }
    }
}

object Lantern {
    /** lantern_version(): the C API version the library was built with. */
    val version: Int get() = Native.version()

    /** The short fingerprint of a SHA-256 ("3F9A 1C07 B2E4 55D0"), to show next to a pairing code. */
    fun shortForm(sha256: ByteArray): String {
        require(sha256.size == 32) { "a SHA-256 is 32 bytes" }
        return Native.shortForm(sha256)
    }
}

internal object Native {
    init {
        System.loadLibrary("lantern_jni")
    }

    external fun version(): Int
    external fun shortForm(sha256: ByteArray): String
    external fun clientCreate(origin: String, userAgent: String, platform: String?, transport: Transport): Long
    external fun clientHandshake(handle: Long): Array<String>?
    external fun clientFree(handle: Long)
}
