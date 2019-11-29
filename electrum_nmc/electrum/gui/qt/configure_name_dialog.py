#!/usr/bin/env python
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2012-2018 Namecoin Developers, Electrum Developers
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

from electrum.bitcoin import TYPE_ADDRESS
from electrum.commands import NameAlreadyExistsError
from electrum.i18n import _
from electrum.names import format_name_identifier, identifier_to_namespace
from electrum.network import TxBroadcastError, BestEffortRequestFailed
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates
from electrum.wallet import InternalAddressCorruption

from .paytoedit import PayToEdit
from .configure_dns_dialog import show_configure_dns

dialogs = []  # Otherwise python randomly garbage collects the dialogs...


def show_configure_name(identifier, value, parent, is_new):
    d = ConfigureNameDialog(identifier, value, parent, is_new)

    dialogs.append(d)
    d.show()


class ConfigureNameDialog(QDialog):
    def __init__(self, identifier, value, parent, is_new):
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)

        self.main_window = parent

        self.setMinimumWidth(545)
        self.setMinimumHeight(245)
        if is_new:
            self.setWindowTitle(_("Configure New Name"))
        else:
            self.setWindowTitle(_("Reconfigure Name"))

        form_layout = QFormLayout()

        self.identifier = identifier
        formatted_name = format_name_identifier(identifier)
        form_layout.addRow(QLabel(formatted_name))

        self.dataEdit = QLineEdit()
        # TODO: support non-ASCII encodings
        self.dataEdit.setText(value.decode('ascii'))

        self.namespace = identifier_to_namespace(identifier)
        self.namespace_is_dns = self.namespace in ["d", "dd"]

        if self.namespace_is_dns:
            self.dnsButton = QPushButton(_('DNS Editor...'))
            self.dnsButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            self.dnsButton.setMinimumSize(150, 0)
            # TODO: tooltip?
            self.dnsButton.clicked.connect(lambda: show_configure_dns(self.dataEdit.text().encode('ascii'), self))

        data_layout = QHBoxLayout()
        data_layout.setContentsMargins(0, 0, 0, 0)
        data_layout.addWidget(self.dataEdit)
        if self.namespace_is_dns:
            data_layout.addWidget(self.dnsButton)

        self.data = QWidget()
        self.data.setLayout(data_layout)

        form_layout.addRow(_("Data:"), self.data)

        self.transferTo = PayToEdit(self.main_window)
        form_layout.addRow(_("Transfer to:"), self.transferTo)

        form = QWidget()
        form.setLayout(form_layout)

        self.buttons_box = QDialogButtonBox()
        self.buttons_box.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)

        buttons_hbox = QHBoxLayout()
        buttons_hbox.addStretch()
        buttons_hbox.addWidget(self.buttons_box)
        buttons = QWidget()
        buttons.setLayout(buttons_hbox)

        vbox = QVBoxLayout()

        vbox.addWidget(form)
        vbox.addWidget(buttons)
        self.setLayout(vbox)

        self.buttons_box.accepted.connect(self.accept)
        self.buttons_box.rejected.connect(self.reject)

        if is_new:
            self.accepted.connect(lambda: self.register_and_broadcast(self.identifier, self.dataEdit.text().encode('ascii'), self.transferTo))
        else:
            # TODO: handle non-ASCII encodings
            self.accepted.connect(lambda: self.update_and_broadcast(self.identifier, self.dataEdit.text().encode('ascii'), self.transferTo))

    def register_and_broadcast(self, identifier, value, transfer_to):
        if transfer_to.toPlainText() == "":
            # User left the recipient blank, so this isn't a transfer.
            recipient_address = None
        else:
            # The user entered something into the recipient text box.

            recipient = transfer_to.get_recipient()

            if recipient is None:
                recipient_type, recipient_address = None, transfer_to.toPlainText()
            else:
                recipient_type, recipient_address = recipient

            if recipient_type != TYPE_ADDRESS:
                self.main_window.show_error(_("Invalid address ") + recipient_address)
                return

        name_autoregister = self.main_window.console.namespace.get('name_autoregister')

        try:
            # TODO: support non-ASCII encodings
            name_autoregister(identifier.decode('ascii'), value.decode('ascii'), recipient_address)
        except NameAlreadyExistsError as e:
            self.main_window.show_message(_("Error registering ") + formatted_name + ": " + str(e))
            return
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            formatted_name = format_name_identifier(identifier)
            self.main_window.show_message(_("Error registering ") + formatted_name + ": " + str(e))
            return
        except InternalAddressCorruption as e:
            formatted_name = format_name_identifier(identifier)
            self.main_window.show_error(_("Error registering ") + formatted_name + ": " + str(e))
            raise
        except TxBroadcastError as e:
            msg = e.get_message_for_gui()
            self.main_window.show_error(msg)
        except BestEffortRequestFailed as e:
            msg = repr(e)
            self.main_window.show_error(msg)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            formatted_name = format_name_identifier(identifier)
            self.main_window.show_message(_("Error registering ") + formatted_name + ": " + str(e))
            return

    def update_and_broadcast(self, identifier, value, transfer_to):
        if transfer_to.toPlainText() == "":
            # User left the recipient blank, so this isn't a transfer.
            recipient_address = None
        else:
            # The user entered something into the recipient text box.

            recipient = transfer_to.get_recipient()

            if recipient is None:
                recipient_type, recipient_address = None, transfer_to.toPlainText()
            else:
                recipient_type, recipient_address = recipient

            if recipient_type != TYPE_ADDRESS:
                self.main_window.show_error(_("Invalid address ") + recipient_address)
                return

        name_update = self.main_window.console.namespace.get('name_update')
        broadcast = self.main_window.console.namespace.get('broadcast')

        try:
            # TODO: support non-ASCII encodings
            tx = name_update(identifier.decode('ascii'), value.decode('ascii'), recipient_address)['hex']
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            formatted_name = format_name_identifier(identifier)
            self.main_window.show_message(_("Error creating update for ") + formatted_name + ": " + str(e))
            return
        except InternalAddressCorruption as e:
            formatted_name = format_name_identifier(identifier)
            self.main_window.show_error(_("Error creating update for ") + formatted_name + ": " + str(e))
            raise
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            formatted_name = format_name_identifier(identifier)
            self.main_window.show_message(_("Error creating update for ") + formatted_name + ": " + str(e))
            return

        try:
            broadcast(tx)
        except Exception as e:
            formatted_name = format_name_identifier(identifier)
            self.main_window.show_error(_("Error broadcasting update for ") + formatted_name + ": " + str(e))
            return

        # As far as I can tell, we don't need to explicitly add the transaction
        # to the wallet, because we're only issuing a single transaction, so
        # there's not much risk of accidental double-spends from subsequent
        # transactions.

