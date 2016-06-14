import mitmproxy

x = None

def start(context):

    global x
    x = mitmproxy.foo