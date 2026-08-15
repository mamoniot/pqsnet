# TODO

## Transport
### Core
- Send handshake messages
- Add session-level approval or rejection of offline key
- Allow for dynamic length payloads
- Handshake resends
- Resumption API
- Socket coherency after resumption
- Handshake and socket expiration
### Extraneous
- Structure init_table as a cache with strict upper limits
- Come up with a better name
- Update protocol full name with new name
- Zeroize stack
- Input sanitize mtu
- Improve desegmentation API
- Improve key bundle timestamp handling
- API for determining maximum allowable payload length
- Implement Debug for all public types
- Add improved timestamp checking API for key bundles

## Session
### Core
- Negotiate limits on the number of channels that can be opened before the next sync, so that the send limits and recv limits may never be exceeded
- Add TTL options for channels and sessions
- Implement PLPMTUD
- Implement phi accural keep alives
- Implement initial timeout negotiation
- Eliminate overflow math
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
