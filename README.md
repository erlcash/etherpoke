Homepage: http://codeward.org/etherpoke

*etherpoke* is a scriptable network session monitor.

*etherpoke* defines three events to which a hook (system command) can be assigned. The event hook can be any program installed in the system.

- __SESSION_BEGIN__ is triggered when the first packet matching the filter rule is captured.
- __SESSION_END__ is triggered when the time since the last matching packet was captured exceeds the session timeout.
- __SESSION_ERROR__ is triggered when it is no longer possible to proceed with packet capture, most likely due to network interface error. This event cancels out any future triggers of __SESSION_END__, until __SESSION_BEGIN__ is triggered again.

Since version 2.3.0, *etherpoke* supports socket notifications (TCP/IP protocol), allowing remote clients to be notified when one of the events is triggered.

*etherpoke* is free software licensed under **GNU GPL3**.
