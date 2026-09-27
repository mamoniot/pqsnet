# TODO

## Dev
- Write development glossary
- Document code architecture

## Transport
### Core
- Add session-level approval or rejection of offline key
- Resumption API
- Handshake and socket expiration
### Extraneous
- Come up with a better name
- Update protocol full name with new name
- Zeroize stack
- Improve desegmentation API
- API for determining maximum allowable payload length
- Implement Debug for all public types
- Improve key bundle timestamp handling
- Add improved timestamp checking API for key bundles
- Add builder API for creating secret key bundles

## Session
Secure, flow controlled, asynchronous, hierarchical document transfer protocol
### Core
- Structure handshake_table as a cache with strict upper limits
- Socket coherency after resumption
- Handshake resends
- Add TTL options for channels and sessions
- Implement PLPMTUD
- Implement phi accural keep alives
- Implement initial timeout negotiation
- Eliminate overflow math
- Add async scheduling of transmission
- Test protocol versioning for backwards compatibility
### Extraneous
- Utalize received ICMP messages (Destination Unreachable, Time Exceeded, Parameter Problem)
- Ensure correct handling of asymmetric routes (https://www.rfc-editor.org/info/rfc3449)
- Implement the nagle algorithm or a variant (https://datatracker.ietf.org/doc/html/draft-minshall-nagle-01)
- Implement delayed acks
- Add support for efficient single segment documents (docs smaller than the mtu)
- Make sure that the protocol would be backwards compatible with the ability to ack packets instead of segments
- Instrument `Instant` with the async runtime for testing
- Add the ability to change stream priorities, and priority fairness for non-prioritized streams.
- Add a configuration option to always pad packets to the length of the plpmtu for enhanced privacy.
- Add an API to make it easy to send inner-mtu sized documents.
- Congestion window recovery on spurious congestion event.
- Metrics
- Tracing
- Reduce and compress repeative code (Until the architecture is settled this is not worth doing
