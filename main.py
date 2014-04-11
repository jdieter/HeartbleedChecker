#!/usr/bin/python
#
# Heartbleed Checker
# Copyright (C) 2014 Jonathan Dieter <jdieter@lesbg.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import kivy
kivy.require('1.0.6')

from kivy.app import App
from kivy.core.window import Window
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
from kivy.uix.image import Image
from kivy.properties import ObjectProperty
import ssltest
import thread
import sys

class Heartbleed(FloatLayout):
    checking = False

    color = (1, 1, 1)
    texture = ObjectProperty()
    bgcolor = ObjectProperty(None)
    work_box = ObjectProperty(None)
    label = ObjectProperty(None)
    server = ObjectProperty(None)
    check_button = ObjectProperty(None)
    label_box = ObjectProperty(None)
    checkbox = None
    connect_data = None
    message_data = None

    GOOD = 0
    VULNERABLE = 1
    INVALID = 2
    DEFAULT = 3

    foreground_color = [(0, 0.3, 0, 1), (0.6, 0, 0, 1), (0, 0, 0, 1), (0.3, 0.3, 0.3, 0.8)]
    background_color = [(0.8, 1.0, 0.8), (1, 0.8, 0.8), (1, 1, 1), (1, 1, 1)]


    def build(self):
        self.texture = Image(source='background-light.png').texture
        self.texture.wrap = 'repeat'
        self.texture.uvsize = (8, 8)
        Window.bind(on_resize=self.on_resize)

    def start(self):
        self.check_button.bind(on_press=self.on_press)
        self.server.bind(on_text_validate=self.on_press)
        self._multi_start()

    def _multi_start(self, *args):
        self.on_resize(None, self.width, self.height)

    def extra_data(self, message):
        return

    def set_color(self, level):
        self.label.color = self.foreground_color[level]

    def show_message(self, level, message):
        if self.checkbox is not None:
            self.label_box.remove_widget(self.checkbox)
            self.checkbox = None

        if level == 0:
            self.checkbox = Image(source='green_tick.png', spacing=0, padding=0, mipmap=True, stretch=True, size_hint = (None, None))
            self.label_box.add_widget(self.checkbox, 1)
        elif level == 1:
            self.checkbox = Image(source='red_x.png', spacing=0, padding=0, mipmap=True, stretch=True, size_hint = (None, None))
            self.label_box.add_widget(self.checkbox, 1)

        self.set_color(level)
        self.label.text = message
        return

    def set_default(self):
        self.show_message(self.DEFAULT, '')

    def on_resize(self, window, width, height): # There *has* to be a better way to do all this!  Insanity!
        if self.server.line_height != 1:
            self.label._label.render()
            self.work_box.height = self.server.minimum_height * 3
            self.work_box.top = ((self.height*2) / 3) + (self.work_box.height / 2)
            self.label.height = self.label.texture_size[1]
            if self.checkbox is not None:
                self.checkbox.size = (self.label.height, self.label.height)
            self.label_box.height = self.label.texture_size[1]
            self.label_box.top=(self.work_box.top - (self.work_box.height + self.server.minimum_height))
        else:
            Clock.schedule_once(self._multi_start, 0.2) # Surely there must be a better way to get the text input to calculate it's line height
        return

    def end_check(self, *args):
        (server, port) = self.connect_data
        (retval, message, verbose) = self.message_data
        print verbose + message
        self.show_message(retval, "%s:%i: %s" % (server, port, message))
        self.extra_data(verbose+message)
        self.connect_data = None
        self.message_data = None
        self.server.text = ""
        self.check_button.disabled = False
        self.server.disabled = False
        self._multi_start()
        self.checking = False

    def check_site(self):
        (server, port) = self.connect_data
        self.message_data = ssltest.hit_hb(server, port)
        # All Kivy stuff must be changed insided of the main Kivy loop
        Clock.schedule_once(self.end_check)

    def on_press(self, instance):
        if self.checking:
            return

        server = self.server.text.strip()
        if server.count(':') == 0:
            port = 443
        elif server.count(':') == 1:
            (server, port) = server.split(':')
            server = server.strip()
            try:
                port = int(port)
            except:
                self.show_message(self.INVALID, 'Invalid input: Port must be a number')
                return
        else:
            self.show_message(self.INVALID, 'Invalid input: You may only use one colon (:)')
            return

        if server == "":
            self.set_default()
            return

        self.checking = True
        Window.release_all_keyboards()
        self.server.disabled = True
        self.check_button.disabled = True

        self.show_message(self.DEFAULT, 'Checking %s:%i...' % (server, port))
        try:
            self.connect_data = (server, port)
            thread.start_new_thread(self.check_site, ())
        except:
            self.show_message(self.INVALID, 'Unable to start new thread to check server')

class HeartbleedApp(App):
    title = 'Heartbleed'
    icon = 'icon.png'

    def build(self):
        self.root = Heartbleed()
        self.root.build()
        return self.root

    def on_pause(self):
        return True

    def on_start(self):
        self.root.start()


if __name__ == '__main__':
    HeartbleedApp().run()
