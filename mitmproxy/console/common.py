from __future__ import absolute_import, print_function, division

import os

import urwid
import urwid.util
import six

import netlib
from mitmproxy import utils
from mitmproxy.console import signals
from mitmproxy.flow import export
from netlib import human

import re
import json

try:
    import pyperclip
except:
    pyperclip = False


VIEW_FLOW_REQUEST = 0
VIEW_FLOW_RESPONSE = 1

METHOD_OPTIONS = [
    ("get", "g"),
    ("post", "p"),
    ("put", "u"),
    ("head", "h"),
    ("trace", "t"),
    ("delete", "d"),
    ("options", "o"),
    ("edit raw", "e"),
]

re_phone = re.compile(r'(\b\d{10}\b)')

# regex caution: useful only for url and form raw data, not multipart form or json post body
re_email = re.compile(r'([^@\/=\?]+(?:@|%40)[^@\/=\?]+\.[^@\/=\?\ ]+)')

re_userid = re.compile(r'(?:[\/=])(\d{4,9})(?:[\?\/&]|$)') #re.compile(r'\b\d{4,7}\b')

re_phone_or_email_or_userid = re.compile(r'(\b\d{10}\b)|([^@\/=\?\ ]+(?:@|%40)[^@\/=\?]+\.[^@\/=\?]+)|(?:[\/=\-])(\d{4,9})(?:[\?\/\s&]|$)')

otp_regex = re.compile(r'^\d{3,6}$')

otp_params = ["pin", "otp", "code", "onetimepass", "onetimepassword"]


def add_key_log(f, key):
    """
        return the flow object after adding this key log
    """
    cur_key_logs = f.key_logs
    if cur_key_logs:
        f.key_logs += "," + str(key)
    else:
        f.key_logs = str(key)

    return f

def parse_qs2(body):
        d = parse_qs(body)
        for k, v in d.iteritems():
                if type(v) == list:
                        d[k] = v[0]

        return d

def process_list(k,v):
        d = {}
        if len(v) > 0: # only first value is taken, maybe all should be taken
                if type(v[0]) == dict:
                        for i in v:
                                d.update(flatten(i))
                elif type(v[0]) == list:
                        for i in v:
                                d.update(process_list(i))
                else:
                        d[k] = v[0]
        else:
                d[k]=""
        return d

def flatten(jsn):
        d = {}
        try:
            jsn = json.loads(jsn)
            for k,v in jsn.iteritems():
                    if type(v) == dict:
                            d.update(flatten(v))
                    elif type(v) == list:
                            d.update(process_list(k,v))
                    else:
                            d[k] = v
        except:
            return d

        return d

def resp_body_contains_otp(body_content, content_type):
        
        try:
                resp_json = json.loads(body_content)
                resp_json_flatten = flatten(resp_json)              

                for k,v in resp_json_flatten.iteritems():                    
                        if (otp_regex.match(str(v)) and str(v) not in ['200', '400', '404', '500']) or "sms" in k.lower() or "otp" in k.lower(): 
                                signals.status_message.send(message="[otp] OTP? %s=%s" % (k,v))
                                return True

                return False

        except ValueError:
                signals.status_message.send(message="[otp]Content type was: %s but no json could be decoded." % content_type)
                return False

        return False

def salt_leakage_in_response(content):
    # ,"salt":"luYFtcEf",
    m = re.findall(r"\bsalt\b[\s\"\']*.{11,13}", content, re.I)
    

    if len(m) > 0:
        
        m = m[0].split(":")
        if len(m) > 1:
            m = m[1]
        else:
            return False

        if len(m.split("\"")) > 1:
            return m.split("\"")[1]
        if len(m.split("'")) > 1:
            return m.split("'")[1]
        return m
            


    return False

def salt_leakage(post_dict, url):
    
    
    is_payu = len(re.findall(r"payu", url, re.I)) > 0

    for key, val in post_dict.iteritems():
          
        # param key matches "salt"
        m = re.search(r".*salt.*", key, re.I)
        if m:
            return val
    
    if is_payu:
        # heuristic based identification of payu call
        for key, val in post_dict.iteritems():
            if not "http" in val:
                continue # assume some surl or curl exists in the val
            
            # or if param value matches 8 character 
            m = re.findall(r"\b[a-zA-Z0-9]{8}\b", val)

            # multiple are misleading, exact 1 is good (chnage if required)
            if len(m) == 1:
                for i in xrange(len(m)):
                    n = re.findall(r"\b[0-9]{8}\b",m[i])
                    p = re.findall(r"\b[a-z]{8}\b",m[i])
                    q = re.findall(r"\b[A-Z]{8}\b",m[i])
                    s = re.findall(r"\b[A-Z0-9]{8}\b",m[i])
                    t = re.findall(r"\b[a-z0-9]{8}\b",m[i])
                    if len(n) + len(p) + len(q) + len(s) + len(t) == 0:
                        signals.status_message.send(message=url + " --- salt -- in the request body---")
                        return m



    return False

def is_keypress(k):
    """
        Is this input event a keypress?
    """
    if isinstance(k, six.string_types):
        return True


def highlight_regex(str, regex, textattr="text", regexattr="key"):
    """
        Like highlight key, this highlights a given regex
    """
    l = []

    ss = regex.finditer(str)

    prev = 0
    for i in ss:

        if i.group(1):
            span_tup = i.span(1)
        if i.group(2):
            span_tup = i.span(2)
        if i.group(3):
            span_tup = i.span(3)
        
        l.append((textattr, str[prev:span_tup[0]]))
        l.append((regexattr, str[span_tup[0]:span_tup[1]]))
        prev = span_tup[1]

    l.append((textattr, str[prev:]))

    return l

def highlight_key(str, key, textattr="text", keyattr="key"):
    l = []
    parts = str.split(key, 1)
    if parts[0]:
        l.append((textattr, parts[0]))
    l.append((keyattr, key))
    if parts[1]:
        l.append((textattr, parts[1]))
    return l


KEY_MAX = 30


def format_keyvals(lst, key="key", val="text", indent=0):
    """
        Format a list of (key, value) tuples.

        If key is None, it's treated specially:
            - We assume a sub-value, and add an extra indent.
            - The value is treated as a pre-formatted list of directives.
    """
    ret = []
    if lst:
        maxk = min(max(len(i[0]) for i in lst if i and i[0]), KEY_MAX)
        for i, kv in enumerate(lst):
            if kv is None:
                ret.append(urwid.Text(""))
            else:
                if isinstance(kv[1], urwid.Widget):
                    v = kv[1]
                elif kv[1] is None:
                    v = urwid.Text("")
                else:
                    v = urwid.Text([(val, kv[1])])
                ret.append(
                    urwid.Columns(
                        [
                            ("fixed", indent, urwid.Text("")),
                            (
                                "fixed",
                                maxk,
                                urwid.Text([(key, kv[0] or "")])
                            ),
                            v
                        ],
                        dividechars = 2
                    )
                )
    return ret


def shortcuts(k):
    if k == " ":
        k = "page down"
    elif k == "ctrl f":
        k = "page down"
    elif k == "ctrl b":
        k = "page up"
    elif k == "j":
        k = "down"
    elif k == "k":
        k = "up"
    return k


def fcol(s, attr):
    s = six.text_type(s)
    return (
        "fixed",
        len(s),
        urwid.Text(
            [
                (attr, s)
            ]
        )
    )

if urwid.util.detected_encoding:
    SYMBOL_REPLAY = u"\u21ba"
    SYMBOL_RETURN = u"\u2190"
    SYMBOL_MARK = u"\u25cf"
    SYMBOL_AUTHORIZATION = u"\u25cf"
    SYMBOL_AUTHENTICATION = u"\u25cf"
    SYMBOL_PAYU_SALT_LEAK = u"\u25cf"
    SYMBOL_OTP_LEAK = u"\u25cf"
else:
    SYMBOL_REPLAY = u"[r]"
    SYMBOL_RETURN = u"<-"
    SYMBOL_MARK = "[m]"
    SYMBOL_AUTHORIZATION = "[ar]"
    SYMBOL_AUTHENTICATION = "[an]"
    SYMBOL_PAYU_SALT_LEAK = "[salt]"
    SYMBOL_OTP_LEAK = "[otp]"


def raw_format_flow(f, focus, extended):
    f = dict(f)
    pile = []
    req = []
    
    if extended:
        req.append(
            fcol(
                human.format_timestamp(f["req_timestamp"]),
                "highlight"
            )
        )
    else:
        req.append(fcol(">>" if focus else "  ", "focus"))

    if f["marked"]:
        req.append(fcol(SYMBOL_MARK, "mark"))

    test_result_color = ["text", "code_200", "code_500", "warn"]

    if f["req_is_replay"]:
        req.append(fcol(SYMBOL_REPLAY, "replay"))
    req.append(fcol(f["req_method"], "method"))

    preamble = sum(i[1] for i in req) + len(req) - 1

    if f["intercepted"] and not f["acked"]:
        uc = "intercept"
    elif "resp_code" in f or "err_msg" in f:
        uc = "text"
    else:
        uc = "title"

    url = f["req_url"]
    if f["req_http_version"] not in ("HTTP/1.0", "HTTP/1.1"):
        url += " " + f["req_http_version"]
    req.append(
        urwid.Text(highlight_regex(url, re_phone_or_email_or_userid, uc))
    )

    pile.append(urwid.Columns(req, dividechars=1))

    resp = []
    resp.append(
        ("fixed", preamble, urwid.Text(""))
    )

    if "resp_code" in f:
        codes = {
	    1: "code_200",
            2: "code_200",
            3: "code_300",
            4: "code_400",
            5: "code_500",
        }
        ccol = codes.get(f["resp_code"] // 100, "code_other")
        resp.append(fcol(SYMBOL_RETURN, ccol))
        if f["resp_is_replay"]:
            resp.append(fcol(SYMBOL_REPLAY, "replay"))
        resp.append(fcol(f["resp_code"], ccol))
        if extended:
            resp.append(fcol(f["resp_reason"], ccol))
        if f["intercepted"] and f["resp_code"] and not f["acked"]:
            rc = "intercept"
        else:
            rc = "text"

        if f["resp_ctype"]:
            resp.append(fcol(f["resp_ctype"], rc))
        resp.append(fcol(f["resp_clen"], rc))
        resp.append(fcol(f["roundtrip"], rc))
        resp.append(fcol(SYMBOL_AUTHENTICATION, test_result_color[f["authentication"]]))
        resp.append(fcol(SYMBOL_AUTHORIZATION, test_result_color[f["authorization"]]))
        resp.append(fcol(SYMBOL_PAYU_SALT_LEAK, test_result_color[f["payu_salt_leak"]]))
        resp.append(fcol(SYMBOL_OTP_LEAK, test_result_color[f["otp_leak"]]))

    elif f["err_msg"]:
        resp.append(fcol(SYMBOL_RETURN, "error"))
        resp.append(
            urwid.Text([
                (
                    "error",
                    f["err_msg"]
                )
            ])
        )
    pile.append(urwid.Columns(resp, dividechars=1))
    return urwid.Pile(pile)


# Save file to disk
def save_data(path, data):
    if not path:
        return
    try:
        if isinstance(data, bytes):
            mode = "wb"
        else:
            mode = "w"
        with open(path, mode) as f:
            f.write(data)
    except IOError as v:
        signals.status_message.send(message=v.strerror)


def ask_save_overwrite(path, data):
    if not path:
        return
    path = os.path.expanduser(path)
    if os.path.exists(path):
        def save_overwrite(k):
            if k == "y":
                save_data(path, data)

        signals.status_prompt_onekey.send(
            prompt = "'" + path + "' already exists. Overwrite?",
            keys = (
                ("yes", "y"),
                ("no", "n"),
            ),
            callback = save_overwrite
        )
    else:
        save_data(path, data)


def ask_save_path(data, prompt="File path"):
    signals.status_prompt_path.send(
        prompt = prompt,
        callback = ask_save_overwrite,
        args = (data, )
    )


def ask_scope_and_callback(flow, cb, *args):
    request_has_content = flow.request and flow.request.raw_content
    response_has_content = flow.response and flow.response.raw_content

    if request_has_content and response_has_content:
        signals.status_prompt_onekey.send(
            prompt = "Save",
            keys = (
                ("request", "q"),
                ("response", "s"),
                ("both", "b"),
            ),
            callback = cb,
            args = (flow,) + args
        )
    elif response_has_content:
        cb("s", flow, *args)
    else:
        cb("q", flow, *args)


def copy_to_clipboard_or_prompt(data):
    # pyperclip calls encode('utf-8') on data to be copied without checking.
    # if data are already encoded that way UnicodeDecodeError is thrown.
    if isinstance(data, bytes):
        toclip = data.decode("utf8", "replace")
    else:
        toclip = data

    try:
        pyperclip.copy(toclip)
    except (RuntimeError, UnicodeDecodeError, AttributeError, TypeError):
        def save(k):
            if k == "y":
                ask_save_path(data, "Save data")
        signals.status_prompt_onekey.send(
            prompt = "Cannot copy data to clipboard. Save as file?",
            keys = (
                ("yes", "y"),
                ("no", "n"),
            ),
            callback = save
        )


def format_flow_data(key, scope, flow):
    data = b""
    if scope in ("q", "b"):
        request = flow.request.copy()
        request.decode(strict=False)
        if request.content is None:
            return None, "Request content is missing"
        if key == "h":
            data += netlib.http.http1.assemble_request(request)
        elif key == "c":
            data += request.get_content(strict=False)
        else:
            raise ValueError("Unknown key: {}".format(key))
    if scope == "b" and flow.request.raw_content and flow.response:
        # Add padding between request and response
        data += b"\r\n" * 2
    if scope in ("s", "b") and flow.response:
        response = flow.response.copy()
        response.decode(strict=False)
        if response.content is None:
            return None, "Response content is missing"
        if key == "h":
            data += netlib.http.http1.assemble_response(response)
        elif key == "c":
            data += response.get_content(strict=False)
        else:
            raise ValueError("Unknown key: {}".format(key))
    return data, False


def handle_flow_data(scope, flow, key, writer):
    """
    key: _c_ontent, _h_eaders+content, _u_rl
    scope: re_q_uest, re_s_ponse, _b_oth
    writer: copy_to_clipboard_or_prompt, ask_save_path
    """
    data, err = format_flow_data(key, scope, flow)

    if err:
        signals.status_message.send(message=err)
        return

    if not data:
        if scope == "q":
            signals.status_message.send(message="No request content.")
        elif scope == "s":
            signals.status_message.send(message="No response content.")
        else:
            signals.status_message.send(message="No content.")
        return

    writer(data)


def ask_save_body(scope, flow):
    """
    Save either the request or the response body to disk.

    scope: re_q_uest, re_s_ponse, _b_oth, None (ask user if necessary)
    """

    request_has_content = flow.request and flow.request.raw_content
    response_has_content = flow.response and flow.response.raw_content

    if scope is None:
        ask_scope_and_callback(flow, ask_save_body)
    elif scope == "q" and request_has_content:
        ask_save_path(
            flow.request.get_content(strict=False),
            "Save request content to"
        )
    elif scope == "s" and response_has_content:
        ask_save_path(
            flow.response.get_content(strict=False),
            "Save response content to"
        )
    elif scope == "b" and request_has_content and response_has_content:
        ask_save_path(
            (flow.request.get_content(strict=False) + b"\n" +
             flow.response.get_content(strict=False)),
            "Save request & response content to"
        )
    else:
        signals.status_message.send(message="No content.")


def export_to_clip_or_file(key, scope, flow, writer):
    """
    Export selected flow to clipboard or a file.

    key:    _c_ontent, _h_eaders+content, _u_rl,
            cu_r_l_command, _p_ython_code,
            _l_ocust_code, locust_t_ask
    scope:  None, _a_ll, re_q_uest, re_s_ponse
    writer: copy_to_clipboard_or_prompt, ask_save_path
    """

    for _, exp_key, exporter in export.EXPORTERS:
        if key == exp_key:
            if exporter is None:  # 'c' & 'h'
                if scope is None:
                    ask_scope_and_callback(flow, handle_flow_data, key, writer)
                else:
                    handle_flow_data(scope, flow, key, writer)
            else:  # other keys
                writer(exporter(flow))

flowcache = utils.LRUCache(800)


def format_flow(f, focus, extended=False, hostheader=False):
    d = dict(
        intercepted = f.intercepted,
        acked = f.reply.state == "committed",

        req_timestamp = f.request.timestamp_start,
        req_is_replay = f.request.is_replay,
        req_method = f.request.method,
        req_url = f.request.pretty_url if hostheader else f.request.url,
        req_http_version = f.request.http_version,

        err_msg = f.error.msg if f.error else None,

        marked = f.marked,

        authorization = f.authorization,
        authentication = f.authentication,
        payu_salt_leak = f.payu_salt_leak,
        otp_leak = f.otp_leak,
    )
    if f.response:
        if f.response.raw_content:
            contentdesc = human.pretty_size(len(f.response.raw_content))
        elif f.response.raw_content is None:
            contentdesc = "[content missing]"
        else:
            contentdesc = "[no content]"
        duration = 0
        if f.response.timestamp_end and f.request.timestamp_start:
            duration = f.response.timestamp_end - f.request.timestamp_start
        roundtrip = human.pretty_duration(duration)

        d.update(dict(
            resp_code = f.response.status_code,
            resp_reason = f.response.reason,
            resp_is_replay = f.response.is_replay,
            resp_clen = contentdesc,
            roundtrip = roundtrip,
        ))
        t = f.response.headers.get("content-type")
        if t:
            d["resp_ctype"] = t.split(";")[0]
        else:
            d["resp_ctype"] = ""
    return flowcache.get(
        raw_format_flow,
        tuple(sorted(d.items())), focus, extended
    )
