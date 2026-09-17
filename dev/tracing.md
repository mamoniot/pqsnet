

## Tracing Conventions
It is very important to me that tracing levels each maintain a consistent semantic meaning throughout the full life-cycle of this project. Levels are very useful for filtering and isolating information in long traces, but only if those levels consistently convey specific known meanings. To that end those meanings are listed below, along with the rules that must be followed to maintain those meanings.

### Trace
### Debug
### Info
### Warn
A warning event must only be fired if the software has encountered an issue which causes it to run in a *seriously degraded or degenerate mode*. The warning should *require the user's attention*. The situations in which a warning may be fired include but are not limited to:

- A remote peer has attempted to breach security, usually by violating authentication.
- The level of security provided by the software is being decreased.
- A remote peer is misbehaving, i.e. they are not following the rules of the protocol.
- The software is out-of-date to the point that it does not recognize new components of the protocol.
- Extremely poor and unusual network behavior is causing degraded performance.

If a developer wishes to fire a warning for a reason not on the list above, they *should* update the list with this new reason.

### Error
An event must only be fired at the "Error" level if a *bug* has occurred somewhere. When one is seen in tracing it must always be a sign of an issue which *requires developer attention* to fix. Spurious errors, errors in response to expected special cases or errors in response to misbehavior from remote peers are *strictly dissallowed*. Errors do not need to be caused by fatal issues, but if possible, fatal issues should fire an error before closing the software.
