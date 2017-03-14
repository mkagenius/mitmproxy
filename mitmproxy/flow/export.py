from __future__ import absolute_import, print_function, division

import json
import re
from textwrap import dedent

import six
from six.moves import urllib

import netlib.http
from datetime import datetime
import pytz

from netlib import version
from netlib import strutils
from netlib.http import cookies
import base64

def format_datetime(dt):
    return dt.replace(tzinfo=pytz.timezone("UTC")).isoformat()

def format_cookies(cookie_list):
    rv = []

    for name, value, attrs in cookie_list:
        cookie_har = {
            "name": name,
            "value": value,
        }

        # HAR only needs some attributes
        for key in ["path", "domain", "comment"]:
            if key in attrs:
                cookie_har[key] = attrs[key]

        # These keys need to be boolean!
        for key in ["httpOnly", "secure"]:
            cookie_har[key] = bool(key in attrs)

        # Expiration time needs to be formatted
        expire_ts = cookies.get_expiration_ts(attrs)
        if expire_ts is not None:
            cookie_har["expires"] = format_datetime(datetime.fromtimestamp(expire_ts))

        rv.append(cookie_har)

    return rv


def format_request_cookies(fields):
    return format_cookies(cookies.group_cookies(fields))


def format_response_cookies(fields):
    return format_cookies((c[0], c[1].value, c[1].attrs) for c in fields)


def name_value(obj):
    """
        Convert (key, value) pairs to HAR format.
    """
    return [{"name": k, "value": v} for k, v in obj.items()]


def _native(s):
    if six.PY2:
        if isinstance(s, six.text_type):
            return s.encode()
    else:
        if isinstance(s, six.binary_type):
            return s.decode()
    return s

def har_format(flow):

    # -1 indicates that these values do not apply to current request
    ssl_time = -1
    connect_time = -1

    if flow.server_conn:
        connect_time = (flow.server_conn.timestamp_tcp_setup -
                        flow.server_conn.timestamp_start)

        if flow.server_conn.timestamp_ssl_setup is not None:
            ssl_time = (flow.server_conn.timestamp_ssl_setup -
                        flow.server_conn.timestamp_tcp_setup)


    # Calculate raw timings from timestamps. DNS timings can not be calculated
    # for lack of a way to measure it. The same goes for HAR blocked.
    # mitmproxy will open a server connection as soon as it receives the host
    # and port from the client connection. So, the time spent waiting is actually
    # spent waiting between request.timestamp_end and response.timestamp_start
    # thus it correlates to HAR wait instead.
    try:
        timings_raw = {
            'send': flow.request.timestamp_end - flow.request.timestamp_start,
            'receive': flow.response.timestamp_end - flow.response.timestamp_start,
            'wait': flow.response.timestamp_start - flow.request.timestamp_end,
            'connect': connect_time,
            'ssl': ssl_time,
        }

        # HAR timings are integers in ms, so we re-encode the raw timings to that format.
        timings = dict([(k, int(1000 * v)) for k, v in timings_raw.items()])
    except:
        timings = dict()

    # full_time is the sum of all timings.
    # Timings set to -1 will be ignored as per spec.
    full_time = sum(v for v in timings.values() if v > -1)

    started_date_time = format_datetime(datetime.utcfromtimestamp(flow.request.timestamp_start))

    response_body_size = -1
    response_body_decoded_size = -1
    response_body_compression = -1
    # Response body size and encoding
    if flow.response and flow.response.raw_content:
        response_body_size = len(flow.response.raw_content)
        response_body_decoded_size = len(flow.response.content)
        response_body_compression = response_body_decoded_size - response_body_size
    
    entry = {
        "testResults":{
            "authentication":flow.authentication,
            "authorization": flow.authorization,
            "otp_leak":flow.otp_leak,
            "payu_salt":flow.payu_salt_leak,
        },
        "keyLogs": flow.key_logs,
        "startedDateTime": started_date_time,
        "time": full_time,
        "request": {
            "method": flow.request.method,
            "url": flow.request.url,
            "httpVersion": flow.request.http_version,
            "cookies": format_request_cookies(flow.request.cookies.fields),
            "headers": name_value(flow.request.headers),
            "queryString": name_value(flow.request.query or {}),
            "headersSize": len(str(flow.request.headers)),
            "bodySize": len(flow.request.content),
        },
        
        "cache": {},
        "timings": timings,
    }

    if flow.response:
        entry["response"] = {
            "status": flow.response.status_code,
            "statusText": flow.response.reason,
            "httpVersion": flow.response.http_version,
            "cookies": format_response_cookies(flow.response.cookies.fields),
            "headers": name_value(flow.response.headers),
            "content": {
                "size": response_body_size,
                "compression": response_body_compression,
                "mimeType": flow.response.headers.get('Content-Type', '')
            },
            "redirectURL": flow.response.headers.get('Location', ''),
            "headersSize": len(str(flow.response.headers)),
            "bodySize": response_body_size,
        }
    # Store binay data as base64
    if strutils.is_mostly_bin(flow.response.content):
        b64 = base64.b64encode(flow.response.content)
        entry["response"]["content"]["text"] = b64.decode('ascii')
        entry["response"]["content"]["encoding"] = "base64"
    else:
        entry["response"]["content"]["text"] = flow.response.text

    if flow.request.method in ["POST", "PUT", "PATCH"]:
        entry["request"]["postData"] = {
            "mimeType": flow.request.headers.get("Content-Type", "").split(";")[0],
            "text": flow.request.content,
            "params": name_value(flow.request.urlencoded_form)
        }

    if flow.server_conn:
        entry["serverIPAddress"] = str(flow.server_conn.ip_address.address[0])

    return entry

def har_format_flows(flows):
    HAR = {}
    HAR.update({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "mitmproxy har_dump",
                "version": "0.1",
                "comment": "mitmproxy version %s" % version.MITMPROXY
            },
            "entries": []
        }
    })
    for f in flows:
        entry = har_format(f)
        HAR["log"]["entries"].append(entry)
    json_dump = json.dumps(HAR, indent=2)
    return json_dump


def dictstr(items, indent):
    lines = []
    for k, v in items:
        lines.append(indent + "%s: %s,\n" % (repr(_native(k)), repr(_native(v))))
    return "{\n%s}\n" % "".join(lines)


def curl_command(flow):
    data = "curl "

    request = flow.request.copy()
    request.decode(strict=False)

    for k, v in request.headers.items(multi=True):
        data += "-H '%s:%s' " % (k, v)

    if request.method != "GET":
        data += "-X %s " % request.method

    full_url = request.scheme + "://" + request.host + request.path
    data += "'%s'" % full_url

    if request.content:
        data += " --data-binary '%s'" % _native(request.content)

    return data


def python_code(flow):
    code = dedent("""
        import requests

        url = '{url}'
        {headers}{params}{data}
        response = requests.request(
            method='{method}',
            url=url,{args}
        )

        print(response.text)
    """).strip()

    components = [urllib.parse.quote(c, safe="") for c in flow.request.path_components]
    url = flow.request.scheme + "://" + flow.request.host + "/" + "/".join(components)

    args = ""
    headers = ""
    if flow.request.headers:
        headers += "\nheaders = %s\n" % dictstr(flow.request.headers.fields, "    ")
        args += "\n    headers=headers,"

    params = ""
    if flow.request.query:
        params = "\nparams = %s\n" % dictstr(flow.request.query.collect(), "    ")
        args += "\n    params=params,"

    data = ""
    if flow.request.body:
        json_obj = is_json(flow.request.headers, flow.request.content)
        if json_obj:
            data = "\njson = %s\n" % dictstr(sorted(json_obj.items()), "    ")
            args += "\n    json=json,"
        else:
            data = "\ndata = '''%s'''\n" % _native(flow.request.content)
            args += "\n    data=data,"

    code = code.format(
        url=url,
        headers=headers,
        params=params,
        data=data,
        method=flow.request.method,
        args=args,
    )
    return code


def is_json(headers, content):
    # type: (netlib.http.Headers, bytes) -> bool
    if headers:
        ct = netlib.http.parse_content_type(headers.get("content-type", ""))
        if ct and "%s/%s" % (ct[0], ct[1]) == "application/json":
            try:
                return json.loads(content.decode("utf8", "surrogateescape"))
            except ValueError:
                return False
    return False


def locust_code(flow):
    code = dedent("""
        from locust import HttpLocust, TaskSet, task

        class UserBehavior(TaskSet):
            def on_start(self):
                ''' on_start is called when a Locust start before any task is scheduled '''
                self.{name}()

            @task()
            def {name}(self):
                url = '{url}'
                {headers}{params}{data}
                self.response = self.client.request(
                    method='{method}',
                    url=url,{args}
                )

            ### Additional tasks can go here ###


        class WebsiteUser(HttpLocust):
            task_set = UserBehavior
            min_wait = 1000
            max_wait = 3000
""").strip()

    components = [urllib.parse.quote(c, safe="") for c in flow.request.path_components]
    name = re.sub('\W|^(?=\d)', '_', "_".join(components))
    if name == "" or name is None:
        new_name = "_".join([str(flow.request.host), str(flow.request.timestamp_start)])
        name = re.sub('\W|^(?=\d)', '_', new_name)

    url = flow.request.scheme + "://" + flow.request.host + "/" + "/".join(components)

    args = ""
    headers = ""
    if flow.request.headers:
        lines = [
            (_native(k), _native(v)) for k, v in flow.request.headers.fields
            if _native(k).lower() not in ["host", "cookie"]
        ]
        lines = ["            '%s': '%s',\n" % (k, v) for k, v in lines]
        headers += "\n        headers = {\n%s        }\n" % "".join(lines)
        args += "\n            headers=headers,"

    params = ""
    if flow.request.query:
        lines = ["            %s: %s,\n" % (repr(k), repr(v)) for k, v in flow.request.query.collect()]
        params = "\n        params = {\n%s        }\n" % "".join(lines)
        args += "\n            params=params,"

    data = ""
    if flow.request.content:
        data = "\n        data = '''%s'''\n" % _native(flow.request.content)
        args += "\n            data=data,"

    code = code.format(
        name=name,
        url=url,
        headers=headers,
        params=params,
        data=data,
        method=flow.request.method,
        args=args,
    )

    host = flow.request.scheme + "://" + flow.request.host
    code = code.replace(host, "' + self.locust.host + '")
    code = code.replace(urllib.parse.quote_plus(host), "' + quote_plus(self.locust.host) + '")
    code = code.replace(urllib.parse.quote(host), "' + quote(self.locust.host) + '")
    code = code.replace("'' + ", "")

    return code


def locust_task(flow):
    code = locust_code(flow)
    start_task = len(code.split('@task')[0]) - 4
    end_task = -19 - len(code.split('### Additional')[1])
    task_code = code[start_task:end_task]

    return task_code


def url(flow):
    return flow.request.url


EXPORTERS = [
    ("content", "c", None),
    ("headers+content", "h", None),
    ("url", "u", url),
    ("as har json", "h", har_format),
    ("as curl command", "r", curl_command),
    ("as python code", "p", python_code),
    ("as locust code", "l", locust_code),
    ("as locust task", "t", locust_task),
]
