Homepage: http://codeward.org/etherpoke

*etherpoke* is scriptable network session monitor.

*etherpoke* defines three events to which a hook (system command) can be assigned. The event hook can be any program installed in the system.

- **SESSION_BEGIN** is triggered when the first packet matching the filter rule is captured.
- **SESSION_END** is triggered when the time since the last matching packet was captured exceeds the session timeout.
- **SESSION_ERROR** is triggered when it is no longer possible to proceed with packet capture, most likely due to network interface error. This event cancels out any future triggers of **SESSION_END**, until **SESSION_BEGIN** is triggered again.

etherpoke is free software licensed under **GNU GPL3**.
