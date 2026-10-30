/*
 * The C++ tests' POSIX adapter behind the C API's callbacks, for the
 * integration tests: plain HTTP on loopback, and a UDP socket. Each goes
 * through lantern_transport_create() and lantern_udp_socket_create(), as an
 * app's own would.
 */
#ifndef LANTERN_TEST_LOOPBACK_H
#define LANTERN_TEST_LOOPBACK_H

#include <stddef.h>

#include <lantern/lantern.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cuts every answer's body after `cut_after` bytes, as a lost connection
 * would (0: never). */
lantern_transport* test_loopback_transport(size_t cut_after);
/* Requests sent by every loopback transport so far. */
size_t test_loopback_requests(void);
lantern_udp_socket* test_udp_socket(void);

#ifdef __cplusplus
}
#endif

#endif
