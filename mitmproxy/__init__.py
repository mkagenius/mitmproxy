_master = None


def log(message, level="info"):
    """
    Logs an event.

    By default, only events with level "error" get displayed. This can be controlled with the "-v" switch.
    How log messages are handled depends on the front-end. mitmdump will print them to stdout,
    mitmproxy sends output to the eventlog for display ("e" keyboard shortcut).
    """
    _master.add_event(message, level)


def duplicate_flow(f):
    """
    Returns a duplicate of the specified flow. The flow is also
    injected into the current state, and is ready for editing, replay,
    etc.
    """
    _master.pause_scripts = True
    f = _master.duplicate_flow(f)
    _master.pause_scripts = False
    return f

# ...