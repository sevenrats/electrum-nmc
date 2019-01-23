#!/usr/bin/env python
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2018 Namecoin Developers
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

from electrum_nmc.commands import NameUpdatedTooRecentlyError
from electrum_nmc.i18n import _
from electrum_nmc.names import format_name_identifier, format_name_value, name_expires_in

from .configure_name_dialog import show_configure_name
from .util import *
from .utxo_list import UTXOList

USER_ROLE_TXOUT = 0
USER_ROLE_NAME = 1
USER_ROLE_VALUE = 2

# TODO: It'd be nice if we could further reduce code duplication against
# UTXOList.
class UNOList(UTXOList):
    filter_columns = [0, 1]  # Name, Value

    def update(self):
        self.wallet = self.parent.wallet
        self.network = self.parent.network
        utxos = self.wallet.get_utxos()
        self.utxo_dict = {}
        self.model().clear()
        self.update_headers([ _('Name'), _('Value'), _('Expires In'), _('Status')])
        for idx, x in enumerate(utxos):
            txid = x.get('prevout_hash')
            vout = x.get('prevout_n')
            name_op = self.wallet.transactions[txid].outputs()[vout].name_op
            if name_op is None:
                continue

            # TODO: Support name_new
            if 'name' in name_op:
                name = name_op['name']
                formatted_name = format_name_identifier(name)
                value = name_op['value']
                formatted_value = format_name_value(value)
            else:
                name = None
                formatted_name = ''
                value = None
                formatted_value = ''

            height = x.get('height')
            chain_height = self.network.blockchain().height()
            expires_in = name_expires_in(height, chain_height)
            formatted_expires_in = '%d'%expires_in if expires_in is not None else ''

            status = '' if expires_in is not None else _('Update Pending')

            txout = txid + ":%d"%vout

            self.utxo_dict[txout] = x

            labels = [formatted_name, formatted_value, formatted_expires_in, status]
            utxo_item = [QStandardItem(x) for x in labels]
            self.set_editability(utxo_item)

            utxo_item[0].setFont(QFont(MONOSPACE_FONT))
            utxo_item[1].setFont(QFont(MONOSPACE_FONT))

            utxo_item[0].setData(txout, Qt.UserRole)
            utxo_item[0].setData(name, Qt.UserRole + USER_ROLE_NAME)
            utxo_item[0].setData(value, Qt.UserRole + USER_ROLE_VALUE)

            address = x.get('address')
            if self.wallet.is_frozen(address):
                utxo_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            self.model().appendRow(utxo_item)

    def create_menu(self, position):
        selected = self.selected_column_0_user_roles()
        if not selected:
            return
        menu = QMenu()

        menu.addAction(_("Renew"), lambda: self.renew_selected_items())
        if len(selected) == 1:
            txid = selected[0].split(':')[0]
            tx = self.wallet.transactions.get(txid)
            if tx:
                label = self.wallet.get_label(txid) or None # Prefer None if empty (None hides the Description: field in the window)
                menu.addAction(_("Configure"), lambda: self.configure_selected_item())
                menu.addAction(_("Transaction Details"), lambda: self.parent.show_transaction(tx, label))

        menu.exec_(self.viewport().mapToGlobal(position))

    # TODO: We should be able to pass a password to this function, which would
    # be used for all name_update calls.  That way, we wouldn't need to prompt
    # the user per name.
    def renew_selected_items(self):
        selected = [x.data(0, Qt.UserRole + USER_ROLE_NAME) for x in self.selectedItems()]
        if not selected:
            return

        name_update = self.parent.console.namespace.get('name_update')
        broadcast = self.parent.console.namespace.get('broadcast')
        addtransaction = self.parent.console.namespace.get('addtransaction')

        for identifier in selected:
            try:
                # TODO: support non-ASCII encodings
                tx = name_update(identifier.decode('ascii'))['hex']
            except NameUpdatedTooRecentlyError:
                # The name was recently updated, so skip it and don't renew.
                continue

            try:
                broadcast(tx)
            except Exception as e:
                formatted_name = format_name_identifier(identifier)
                self.parent.show_error(_("Error broadcasting renewal for ") + formatted_name + ": " + str(e))
                continue

            # We add the transaction to the wallet explicitly because
            # otherwise, the wallet will only learn that the transaction's
            # inputs are spent once the ElectrumX server sends us a copy of the
            # transaction, which is several seconds later, which will cause us
            # to double-spend those inputs in subsequent renewals during this
            # loop.
            status = addtransaction(tx)
            if not status:
                formatted_name = format_name_identifier(identifier)
                self.parent.show_error(_("Error adding renewal for ") + formatted_name + _(" to wallet"))
                continue

    def configure_selected_item(self):
        selected = [(x.data(0, Qt.UserRole + USER_ROLE_NAME), x.data(0, Qt.UserRole + USER_ROLE_VALUE)) for x in self.selectedItems()]
        if not selected:
            return
        if len(selected) != 1:
            return

        identifier, initial_value = selected[0]

        show_configure_name(identifier, initial_value, self.parent, False)

