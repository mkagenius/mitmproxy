from __future__ import absolute_import, print_function, division

import urwid

import netlib.http.url
from mitmproxy.console import common
from mitmproxy.console import signals
from mitmproxy.flow import export

import time
import re

import urlparse

def _mkhelp():
    text = []
    keys = [
        ("A", "accept all intercepted flows"),
        ("a", "accept this intercepted flow"),
        ("b", "save request/response body"),
        ("C", "export flow to clipboard"),
        ("d", "delete flow"),
        ("D", "duplicate flow"),
        ("e", "toggle eventlog"),
        ("f", "filter view"),
        ("F", "toggle follow flow list"),
        ("L", "load saved flows"),
        ("m", "toggle flow mark"),
        ("M", "toggle marked flow view"),
        ("n", "create a new request"),
        ("E", "export flow to file"),
        ("r", "replay request"),
        ("U", "unmark all marked flows"),
        ("V", "revert changes to request"),
        ("w", "save flows "),
        ("W", "stream flows to file"),
        ("X", "kill and delete flow, even if it's mid-intercept"),
        ("z", "clear flow list or eventlog"),
        ("tab", "tab between eventlog and flow list"),
        ("enter", "view flow"),
        ("|", "run script on this flow"),
    ]
    text.extend(common.format_keyvals(keys, key="key", val="text", indent=4))
    return text
help_context = _mkhelp()

footer = [
    ('heading_key', "?"), ":help ",
]


class LogBufferBox(urwid.ListBox):

    def __init__(self, master):
        self.master = master
        urwid.ListBox.__init__(self, master.logbuffer)

    def keypress(self, size, key):
        key = common.shortcuts(key)
        if key == "z":
            self.master.clear_events()
            key = None
        elif key == "G":
            self.set_focus(len(self.master.logbuffer) - 1)
        elif key == "g":
            self.set_focus(0)
        return urwid.ListBox.keypress(self, size, key)


class BodyPile(urwid.Pile):

    def __init__(self, master):
        h = urwid.Text("Event log")
        h = urwid.Padding(h, align="left", width=("relative", 100))

        self.inactive_header = urwid.AttrWrap(h, "heading_inactive")
        self.active_header = urwid.AttrWrap(h, "heading")

        urwid.Pile.__init__(
            self,
            [
                FlowListBox(master),
                urwid.Frame(
                    LogBufferBox(master),
                    header = self.inactive_header
                )
            ]
        )
        self.master = master

    def keypress(self, size, key):
        if key == "tab":
            self.focus_position = (
                self.focus_position + 1) % len(self.widget_list)
            if self.focus_position == 1:
                self.widget_list[1].header = self.active_header
            else:
                self.widget_list[1].header = self.inactive_header
            key = None
        elif key == "e":
            self.master.toggle_eventlog()
            key = None

        # This is essentially a copypasta from urwid.Pile's keypress handler.
        # So much for "closed for modification, but open for extension".
        item_rows = None
        if len(size) == 2:
            item_rows = self.get_item_rows(size, focus = True)
        i = self.widget_list.index(self.focus_item)
        tsize = self.get_item_size(size, i, True, item_rows)
        return self.focus_item.keypress(tsize, key)


class ConnectionItem(urwid.WidgetWrap):

    def __init__(self, master, state, flow, focus):
        self.master, self.state, self.flow = master, state, flow
        self.f = focus
        w = self.get_text()
        urwid.WidgetWrap.__init__(self, w)

    def get_text(self):
        cols, _ = self.master.ui.get_cols_rows()
        return common.format_flow(
            self.flow,
            self.f,
            hostheader=self.master.options.showhost,
            max_url_len=cols,
        )

    def selectable(self):
        return True

    def save_flows_prompt(self, k):
        if k == "l":
            signals.status_prompt_path.send(
                prompt = "Save listed flows to",
                callback = self.master.save_flows
            )
        else:
            signals.status_prompt_path.send(
                prompt = "Save this flow to",
                callback = self.master.save_one_flow,
                args = (self.flow,)
            )

    def stop_server_playback_prompt(self, a):
        if a != "n":
            self.master.stop_server_playback()

    def server_replay_prompt(self, k):
        if k == "a":
            self.master.start_server_playback(
                [i.copy() for i in self.master.state.view],
                self.master.options.replay_kill_extra, self.master.options.server_replay_use_headers,
                False, self.master.options.server_replay_nopop,
                self.master.options.server_replay_ignore_params,
                self.master.options.server_replay_ignore_content,
                self.master.options.server_replay_ignore_payload_params,
                self.master.options.server_replay_ignore_host
            )
        elif k == "t":
            self.master.start_server_playback(
                [self.flow.copy()],
                self.master.options.replay_kill_extra, self.master.options.server_replay_use_headers,
                False, self.master.options.server_replay_nopop,
                self.master.options.server_replay_ignore_params,
                self.master.options.server_replay_ignore_content,
                self.master.options.server_replay_ignore_payload_params,
                self.master.options.server_replay_ignore_host
            )
        else:
            signals.status_prompt_path.send(
                prompt = "Server replay path",
                callback = self.master.server_playback_path
            )

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            if self.flow.request:
                self.master.view_flow(self.flow)
                return True


    def remove_auth(self, headers):
        if 'authorization' in headers:
            headers.set_all('authorization', [])
        if 'Authorization' in headers:
            headers.set_all('Authorization', [])
        if 'X-Authorization' in headers:
            headers.set_all('X-Authorization', [])
        if 'Cookie' in headers:
            headers.set_all('Cookie', [])
        if 'cookie' in headers:
            headers.set_all('cookie', [])
        return headers

    def revert_to_original(self):
        if not self.flow.modified():
                signals.status_message.send(message="Flow not modified.")
                return
        self.state.revert(self.flow)
        signals.flowlist_change.send(self)
        signals.status_message.send(message="Reverted.")

    def test_authentication(self, f):
        if not f.response:
            return 0
        #self.flow.backup()
        prev_response = f.response
        signals.status_message.send(message="Testing authentication.")
        f.request.headers = self.remove_auth(f.request.headers)
        r = self.master.replay_request(f)
        return 3

    def test_payu_salt_leak(self, f):
        
        signals.status_message.send(message="Testing payu salt leak.")
        # f.request.headers = self.remove_auth(f.request.headers)
        found_salt = False
        if f.request.content:
            post_str = f.request.content
            post_dict = dict(urlparse.parse_qsl(post_str))
            found_salt = common.salt_leakage(post_dict, f.request.url)

        if f.response.content:
            found_salt = common.salt_leakage_in_response(f.response.content)

        if found_salt: 
            return 2 # bug found
        return 1 # no bug

    def test_otp_leak(self, f):
        
        prev_response = f.response
        signals.status_message.send(message="Testing otp leak")
        # f.request.headers = self.remove_auth(f.request.headers)
        content_type = ""
        if "content-type" in f.request.headers:
            content_type = f.request.headers["content-type"]
        elif "Content-Type" in f.request.headers:
            content_type = f.request.headers["Content-Type"]
        
        if "json" in content_type.lower() and common.resp_body_contains_otp(f.response.content, content_type):
            return 2
        else:
            return 1

    def edit_url(self, regex, url):
        ret = ""

        ss = regex.finditer(url)

        prev = 0
        for i in ss:
            span_tup = i.span()
            ret += url[prev:span_tup[0]]
            ret += str(int(url[span_tup[0]:span_tup[1]]) - 1)
            prev = span_tup[1]

        ret += url[prev:]

        return ret


    def test_authorization(self, f):
        if not f.response:
            return 0
        #self.flow.backup()
        prev_response = f.response
        signals.status_message.send(message="Testing authorization.")

        f.request.headers = self.remove_auth(f.request.headers)

        re_phone_or_email_or_userid = re.compile(r'(?:\b\d{10}\b)|(?:[^@\/=\?\ ]+(@|%40)[^@\/=\?]+\.[^@\/=\?]+)|(?:\b\d{4,8}\b)')

        # email replaced with some test account email
        re_email = re.compile(r'[^@\/=\?]+(@|%40)[^@\/=\?]+\.[^@\/=\?\ ]+')

        # phone replaced with some test account phone
        re_phone = re.compile(r'\b\d{10}\b')

        # user id / card id / other id decreased by 1
        re_userid = re.compile(r'\b\d{4,8}\b')
        f.request.url = self.edit_url(re_userid, f.request.url)
        signals.status_message.send(message="Edited url: " + f.request.url)
        r = self.master.replay_request(f)
        return 3

    def gather_authentication_result(self, f):
        if "backup" not in f.get_state():
            signals.status_message.send(message="No backup found..maybe you checked result too fast.")
            return 0
        backup_flow = f.get_state()["backup"]
        if f.response.content == backup_flow["response"]["content"]:
            return 2 # auth broken
        else:
            return 1

        return 0

    def is_different_data(self, new_resp, old_resp):
        content_type = ""
        if "content-type" in new_resp.headers:
            content_type = new_resp.headers["content-type"]
        elif "Content-Type" in new_resp.headers:
            content_type = new_resp.headers["Content-Type"]

        if "json" in content_type:
            old_resp_dict = common.flatten(old_resp["content"])
            new_resp_dict = common.flatten(new_resp.content)

            keys_old = old_resp_dict.keys()
            keys_new = new_resp_dict.keys()

            cnt = 0
            match_cnt = 0
            value_match_cnt = 0
            for k in keys_old:
                cnt += 1
                if k in keys_new:
                    match_cnt+=1
                    if old_resp_dict[k] == new_resp_dict[k]:
                        value_match_cnt += 1

            if value_match_cnt == match_cnt:
                return False # even same values

            if match_cnt / (cnt * 1.0) * 100.0 > 90.0 :
                return True # different values, almost same keys

            return False
        else:
            if "error" in new_resp.content.lower(): # anything better than error keyword?
                return False # if error happened then its not a data leak
            return True # if error not happened then its a data leak

    def gather_authorization_result(self, f):
        if "backup" not in f.get_state():
            signals.status_message.send(message="No backup found..maybe you checked result too fast.")
            return 0
        backup_flow = f.get_state()["backup"]

        ## TODO test if response contains data different than this but some user data
        if f.response.status_code >= 200 and f.response.status_code < 300:
            
            

            if f.response.content == backup_flow["response"]["content"]:
                return 1 # authorization is done via cookies or something
            elif self.is_different_data(f.response, backup_flow["response"]): # same type of data content came back, but not exact
                return 2
            else:
                return 1
        else:
            return 1

        return 0

    def keypress(self, xxx_todo_changeme, key):
        (maxcol,) = xxx_todo_changeme
        key = common.shortcuts(key)

        if key == "1":
            for f in self.state.flows:
                if f.marked:
                    f.authentication = self.test_authentication(f)
                    signals.flowlist_change.send(self)

        if key == "2":
            for f in self.state.flows:
                if f.marked:
                    f.authentication = self.gather_authentication_result(f)
                    signals.flowlist_change.send(self)

        if key == "3":
            cnt = 1
            for f in self.state.flows:
                if f.marked:
                    f.authorization = self.test_authorization(f)
                    signals.flowlist_change.send(self)

        if key == "4":
            for f in self.state.flows:
                if f.marked:
                    f.authorization = self.gather_authorization_result(f)
                    signals.flowlist_change.send(self)

        # payu salt in req or resp
        if key == "5":
            for f in self.state.flows:
                if f.marked:
                    f.payu_salt_leak = self.test_payu_salt_leak(f)
                    signals.flowlist_change.send(self) 

        # otp in resp
        if key == "6":
            for f in self.state.flows:
                if f.marked:
                    f.otp_leak = self.test_otp_leak(f)
                    signals.flowlist_change.send(self)


        if key == "a":
            self.flow.accept_intercept(self.master)
            signals.flowlist_change.send(self)
        elif key == "d":
            if self.flow.killable:
                self.flow.kill(self.master)
            self.state.delete_flow(self.flow)
            signals.flowlist_change.send(self)
        elif key == "D":
            f = self.master.duplicate_flow(self.flow)
            self.master.state.set_focus_flow(f)
            signals.flowlist_change.send(self)
        elif key == "m":
            self.flow.marked = not self.flow.marked
            signals.flowlist_change.send(self)
        elif key == "M":
            if self.state.mark_filter:
                self.state.disable_marked_filter()
            else:
                self.state.enable_marked_filter()
            signals.flowlist_change.send(self)
        elif key == "N":
            
            self.state.set_view_filter("!(.js) & !(.css) & !(.ttf) & !(.png) & !(.svg) & !(gstatic) & !(.ico) & !(.jpg) & !(.jpeg) & !(.woff) & !(.woff2) & !(fbcdn) & !(google) & !(facebook)")
            signals.flowlist_change.send(self)
        elif key == "r":
            r = self.master.replay_request(self.flow)
            if r:
                signals.status_message.send(message=r)
            signals.flowlist_change.send(self)
        elif key == "S":
            if not self.master.server_playback:
                signals.status_prompt_onekey.send(
                    prompt = "Server Replay",
                    keys = (
                        ("all flows", "a"),
                        ("this flow", "t"),
                        ("file", "f"),
                    ),
                    callback = self.server_replay_prompt,
                )
            else:
                signals.status_prompt_onekey.send(
                    prompt = "Stop current server replay?",
                    keys = (
                        ("yes", "y"),
                        ("no", "n"),
                    ),
                    callback = self.stop_server_playback_prompt,
                )
        elif key == "U":
            for f in self.state.flows:
                f.marked = False
            signals.flowlist_change.send(self)
        elif key == "V":
            if not self.flow.modified():
                signals.status_message.send(message="Flow not modified.")
                return
            self.state.revert(self.flow)
            signals.flowlist_change.send(self)
            signals.status_message.send(message="Reverted.")
        elif key == "w":
            signals.status_prompt_onekey.send(
                self,
                prompt = "Save",
                keys = (
                    ("listed flows", "l"),
                    ("this flow", "t"),
                ),
                callback = self.save_flows_prompt,
            )
        elif key == "X":
            if self.flow.killable:
                self.flow.kill(self.master)
        elif key == "enter":
            if self.flow.request:
                self.master.view_flow(self.flow)
        elif key == "|":
            signals.status_prompt_path.send(
                prompt = "Send flow to script",
                callback = self.master.run_script_once,
                args = (self.flow,)
            )
        elif key == "E":
            signals.status_prompt_onekey.send(
                self,
                prompt = "Export to file",
                keys = [(e[0], e[1]) for e in export.EXPORTERS],
                callback = common.export_to_clip_or_file,
                args = (None, self.flow, common.ask_save_path)
            )
        elif key == "C":
            signals.status_prompt_onekey.send(
                self,
                prompt = "Export to clipboard",
                keys = [(e[0], e[1]) for e in export.EXPORTERS],
                callback = common.export_to_clip_or_file,
                args = (None, self.flow, common.copy_to_clipboard_or_prompt)
            )
        elif key == "b":
            common.ask_save_body(None, self.flow)
        else:
            return key


class FlowListWalker(urwid.ListWalker):

    def __init__(self, master, state):
        self.master, self.state = master, state
        signals.flowlist_change.connect(self.sig_flowlist_change)

    def sig_flowlist_change(self, sender):
        self._modified()

    def get_focus(self):
        f, i = self.state.get_focus()
        f = ConnectionItem(self.master, self.state, f, True) if f else None
        return f, i

    def set_focus(self, focus):
        ret = self.state.set_focus(focus)
        return ret

    def get_next(self, pos):
        f, i = self.state.get_next(pos)
        f = ConnectionItem(self.master, self.state, f, False) if f else None
        return f, i

    def get_prev(self, pos):
        f, i = self.state.get_prev(pos)
        f = ConnectionItem(self.master, self.state, f, False) if f else None
        return f, i


class FlowListBox(urwid.ListBox):

    def __init__(self, master):
        # type: (mitmproxy.console.master.ConsoleMaster) -> None
        self.master = master
        super(FlowListBox, self).__init__(FlowListWalker(master, master.state))

    def get_method_raw(self, k):
        if k:
            self.get_url(k)

    def get_method(self, k):
        if k == "e":
            signals.status_prompt.send(
                self,
                prompt = "Method",
                text = "",
                callback = self.get_method_raw
            )
        else:
            method = ""
            for i in common.METHOD_OPTIONS:
                if i[1] == k:
                    method = i[0].upper()
            self.get_url(method)

    def get_url(self, method):
        signals.status_prompt.send(
            prompt = "URL",
            text = "http://www.example.com/",
            callback = self.new_request,
            args = (method,)
        )

    def new_request(self, url, method):
        parts = netlib.http.url.parse(str(url))
        if not parts:
            signals.status_message.send(message="Invalid Url")
            return
        scheme, host, port, path = parts
        f = self.master.create_request(method, scheme, host, port, path)
        self.master.state.set_focus_flow(f)
        signals.flowlist_change.send(self)

    def keypress(self, size, key):
        key = common.shortcuts(key)
        if key == "A":
            self.master.accept_all()
            signals.flowlist_change.send(self)
        elif key == "z":
            self.master.clear_flows()
        elif key == "e":
            self.master.toggle_eventlog()
        elif key == "g":
            self.master.state.set_focus(0)
            signals.flowlist_change.send(self)
        elif key == "G":
            self.master.state.set_focus(self.master.state.flow_count())
            signals.flowlist_change.send(self)
        elif key == "f":
            signals.status_prompt.send(
                prompt = "Filter View",
                text = self.master.state.filter_txt,
                callback = self.master.set_view_filter
            )
        elif key == "L":
            signals.status_prompt_path.send(
                self,
                prompt = "Load flows",
                callback = self.master.load_flows_callback
            )
        elif key == "n":
            signals.status_prompt_onekey.send(
                prompt = "Method",
                keys = common.METHOD_OPTIONS,
                callback = self.get_method
            )
        elif key == "F":
            self.master.toggle_follow_flows()
        elif key == "W":
            if self.master.options.outfile:
                self.master.options.outfile = None
            else:
                signals.status_prompt_path.send(
                    self,
                    prompt="Stream flows to",
                    callback= lambda path: self.master.options.update(outfile=(path, "ab"))
                )
        else:
            return urwid.ListBox.keypress(self, size, key)
