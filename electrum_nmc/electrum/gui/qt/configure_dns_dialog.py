#!/usr/bin/env python
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2012-2019 Namecoin Developers, Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import traceback

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .forms.dnsdialog import Ui_DNSDialog

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_configure_dns(value, parent):
    d = ConfigureDNSDialog(value, parent)

    dialogs.append(d)
    d.show()

class ConfigureDNSDialog(QDialog):
    def __init__(self, value, parent):
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)

        self.name_dialog = parent

        self.ui = Ui_DNSDialog()
        self.ui.setupUi(self)

        identifier = self.name_dialog.identifier.decode('ascii')
        if self.name_dialog.namespace == "d":
            self.base_domain = identifier[len("d/"):] + ".bit"
        elif self.name_dialog.namespace == "dd":
            self.base_domain = "(...).bit"
        else:
            raise Exception("Identifier '" + identifier + "' is not d/ or dd/")
        subdomains = [self.base_domain]
        self.ui.comboDomain.addItems(subdomains)

