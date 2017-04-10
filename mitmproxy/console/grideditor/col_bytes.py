from __future__ import absolute_import, print_function, division

import os

import urwid
from mitmproxy.console import signals
from mitmproxy.console.grideditor import base
from netlib import strutils

import base64
import urllib

def read_file(filename, callback, escaped):
    # type: (str, Callable[...,None], bool) -> Optional[str]
    if not filename:
        return

    filename = os.path.expanduser(filename)
    try:
        with open(filename, "r" if escaped else "rb") as f:
            d = f.read()
    except IOError as v:
        return str(v)

    if escaped:
        try:
            d = strutils.escaped_str_to_bytes(d)
        except ValueError:
            return "Invalid Python-style string encoding."
    # TODO: Refactor the status_prompt_path signal so that we
    # can raise exceptions here and return the content instead.
    callback(d)


class Column(base.Column):
    def Display(self, data):
        return Display(data)

    def Edit(self, data):
        return Edit(data)

    def blank(self):
        return b""

    def get_number_start_idx(self, o):
        idx = len(o)
        for i in xrange(len(o)):
            if o[len(o) - i - 1] in '0123456789':
                idx = i
            else:
                break
        return len(o) - idx - 1

    def keypress(self, key, editor):
        if key == "r":
            if editor.walker.get_current_value() is not None:
                signals.status_prompt_path.send(
                    self,
                    prompt = "Read file",
                    args=(editor.walker.set_current_value, True),
                    callback = read_file
                )
        elif key == "R":
            if editor.walker.get_current_value() is not None:
                signals.status_prompt_path.send(
                    self,
                    prompt = "Read unescaped file",
                    callback = read_file,
                    args=(editor.walker.set_current_value, False)
                )
        elif key == "e":
            o = editor.walker.get_current_value()
            if o is not None:
                n = editor.master.spawn_editor(o.encode("string-escape"))
                n = strutils.clean_hanging_newline(n)
                editor.walker.set_current_value(n)

        elif key == "D":
            # base64 decode
            o = editor.walker.get_current_value()
            if o is not None:
                try:
                    if ' ' in o:
                        parts = o.split(' ', 1)
                        if len(parts) == 2:
                            b64decoded_val = parts[0] + ' ' + base64.b64decode(parts[1])
                    else:
                        b64decoded_val = base64.b64decode(o)
                except:
                    b64decoded_val = o
                editor.walker.set_current_value(b64decoded_val)
                editor.walker._modified()
        elif key == "E":
            # base64 encode
            o = editor.walker.get_current_value()
            if o is not None:
                try:
                    if ' ' in o:
                        parts = o.split(' ', 1)
                        if len(parts) == 2:
                            b64encoded_val = parts[0] + ' ' + base64.b64encode(parts[1])
                    else:
                        b64encoded_val = base64.b64encode(o)
                except:
                    b64encoded_val = o
                editor.walker.set_current_value(b64encoded_val)
                editor.walker._modified()
        elif key == "p":
            # increase a number by 1
            o = editor.walker.get_current_value()
            try:
                idx = self.get_number_start_idx(o)
                part1 = o[0:idx]
                part2 = o[idx:]
                part2 = str(int(part2) + 1)
                n = part1 + part2
            except:
                n = o
            editor.walker.set_current_value(n)
            editor.walker._modified()
        elif key == "m":
            # increase a number by 1
            o = editor.walker.get_current_value()
            try:
                idx = self.get_number_start_idx(o)
                part1 = o[0:idx]
                part2 = o[idx:]
                part2 = str(int(part2) - 1)
                n = part1 + part2
            except:
                n = o
            editor.walker.set_current_value(n)
            editor.walker._modified()
        elif key == "n":
            o = editor.walker.get_current_value()

            n = "mkagenius1@gmail.com"
            editor.walker.set_current_value(n)
            editor.walker._modified()
        elif key == "u":
            o = editor.walker.get_current_value()
            try:
                n = urllib.unquote_plus(o)
            except:
                n = o
            editor.walker.set_current_value(n)
            editor.walker._modified()

        elif key in ["enter"]:
            editor.walker.start_edit()
        else:
            return key



class Display(base.Cell):
    def __init__(self, data):
        # type: (bytes) -> Display
        self.data = data
        escaped = strutils.bytes_to_escaped_str(data)
        w = urwid.Text(escaped, wrap="any")
        super(Display, self).__init__(w)

    def get_data(self):
        return self.data


class Edit(base.Cell):
    def __init__(self, data):
        # type: (bytes) -> Edit
        data = strutils.bytes_to_escaped_str(data)
        w = urwid.Edit(edit_text=data, wrap="any", multiline=True)
        w = urwid.AttrWrap(w, "editfield")
        super(Edit, self).__init__(w)

    def get_data(self):
        # type: () -> bytes
        txt = self._w.get_text()[0].strip()
        try:
            return strutils.escaped_str_to_bytes(txt)
        except ValueError:
            signals.status_message.send(
                self,
                message="Invalid Python-style string encoding.",
                expire=1000
            )
            raise
