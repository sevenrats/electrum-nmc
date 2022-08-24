#!/usr/bin/env python
#
# Electrum-NMC - lightweight Namecoin client
# Copyright (C) 2012-2022 Namecoin Developers, Electrum Developers
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

from decimal import Decimal
import sys
import traceback

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electrum.bitcoin import COIN
from electrum.i18n import _
from electrum.names import format_name_identifier, format_name_identifier_split, identifier_to_namespace
from electrum.network import TxBroadcastError, BestEffortRequestFailed
from electrum.transaction import Transaction
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, is_hex_str
from electrum.wallet import InternalAddressCorruption

from .forms.tradenamedialog import Ui_TradeNameDialog
from .amountedit import AmountEdit, BTCAmountEdit
from .configure_dns_dialog import show_configure_dns
from .qrtextedit import ScanQRTextEdit
from .util import ButtonsTextEdit, ColorScheme, MessageBoxMixin, MONOSPACE_FONT, TRANSACTION_FILE_EXTENSION_FILTER_SEPARATE, TRANSACTION_FILE_EXTENSION_FILTER_ONLY_COMPLETE_TX

dialogs = []  # Otherwise python randomly garbage collects the dialogs...


def show_trade_name(identifier, value, parent, buy):
    d = TradeNameDialog(identifier, value, parent, buy=buy)

    dialogs.append(d)
    d.show()


class TradeNameDialog(QDialog, MessageBoxMixin):
    def __init__(self, identifier, value, parent, buy):
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)

        self.main_window = parent
        self.wallet = self.main_window.wallet

        self.ui = Ui_TradeNameDialog()
        self.ui.setupUi(self)

        if buy:
            self.setWindowTitle(_("Buy Name"))
            self.ui.amountLabel.setText(_("Amount to offer:"))
            self.ui.labelOffer.setText(_("Sell Offer to accept:"))
        else:
            self.setWindowTitle(_("Sell Name"))
            self.ui.amountLabel.setText(_("Requested amount:"))
            self.ui.labelOffer.setText(_("Buy Offer to accept:"))

        self.identifier = identifier
        self.buy = buy

        # TODO: handle non-ASCII encodings
        self.ui.buttonBox.accepted.connect(lambda: self.trade(self.identifier, self.ui.dataEdit.text().encode('ascii'), self.amount_edit.get_amount(), self.ui.transferTo, self.input_offer.toPlainText()))

        formatted_name_split = format_name_identifier_split(self.identifier)
        self.ui.labelNamespace.setText(formatted_name_split.category + ":")
        self.ui.labelName.setText(formatted_name_split.specifics)

        self.amount_edit = BTCAmountEdit(self.main_window.get_decimal_point)
        old_amount_edit = self.ui.horizontalLayout_amountEdit.replaceWidget(self.ui.amountEdit, self.amount_edit)
        self.ui.amountEdit = self.amount_edit
        old_amount_edit.widget().setParent(None)

        self.fiat_amount_edit = AmountEdit(self.main_window.fx.get_currency if self.main_window.fx else '')
        if not self.main_window.fx or not self.main_window.fx.is_enabled():
            self.fiat_amount_edit.hide()
        old_fiat_amount_edit = self.ui.horizontalLayout_amountEdit.replaceWidget(self.ui.fiatAmountEdit, self.fiat_amount_edit)
        self.ui.fiatAmountEdit = self.fiat_amount_edit
        old_fiat_amount_edit.widget().setParent(None)

        self.main_window.connect_fields(self.main_window, self.amount_edit, self.fiat_amount_edit, None)

        self.input_offer = ScanQRTextEdit()
        self.input_offer.setMaximumHeight(self.ui.inputOffer.maximumHeight())
        old_input_offer = self.ui.verticalLayout.replaceWidget(self.ui.inputOffer, self.input_offer)
        self.ui.inputOffer = self.input_offer
        old_input_offer.widget().setParent(None)
        self.input_offer.setFont(QFont(MONOSPACE_FONT))
        self.input_offer.addPasteButton(self.main_window.app)

        self.submit_sell_hint = self.ui.labelSubmitSellHint
        self.submit_buy_hint = self.ui.labelSubmitBuyHint
        if buy:
            self.submit_sell_hint.hide()
            self.submit_buy_hint.show()

            self.namespace = identifier_to_namespace(self.identifier)
            self.namespace_is_dns = self.namespace in ["d", "dd"]

            self.ui.btnDNSEditor.setVisible(self.namespace_is_dns)
            self.ui.btnDNSEditor.clicked.connect(lambda: show_configure_dns(self.ui.dataEdit.text().encode('ascii'), self))
        else:
            self.submit_sell_hint.show()
            self.submit_buy_hint.hide()

            self.ui.dataLabel.hide()
            self.ui.dataEdit.hide()
            self.ui.btnDNSEditor.hide()
            self.ui.dataHintLabel.hide()

            self.ui.labelTransferTo.hide()
            self.ui.transferTo.hide()
            self.ui.labelTransferToHint.hide()

        self.output_offer = ButtonsTextEdit()
        self.output_offer.setReadOnly(self.ui.outputOffer.isReadOnly())
        self.output_offer.setMaximumHeight(self.ui.outputOffer.maximumHeight())
        old_output_offer = self.ui.verticalLayout.replaceWidget(self.ui.outputOffer, self.output_offer)
        self.ui.outputOffer = self.output_offer
        old_output_offer.widget().setParent(None)
        self.output_offer.setFont(QFont(MONOSPACE_FONT))
        self.output_offer.addCopyButton(self.main_window.app)
        qr_icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.output_offer.addButton(qr_icon, lambda: self.show_qr(self.output_offer.toPlainText()), _("Show as QR code"))
        export_icon = "file.png"
        self.output_offer.addButton(export_icon, lambda: self.export_to_file(self.output_offer.toPlainText()), _("Export to file"))

        self.output_offer_sell_hint = self.ui.labelOutputSellHint
        self.output_offer_buy_hint = self.ui.labelOutputBuyHint
        self.hide_output_offer()

        if buy:
            self.set_value(value)

        self.amount_edit.textChanged.connect(self.hide_output_offer)
        self.input_offer.textChanged.connect(self.hide_output_offer)
        self.ui.dataEdit.textChanged.connect(self.hide_output_offer)
        self.ui.transferTo.textChanged.connect(self.hide_output_offer)

    def set_value(self, value):
        # TODO: support non-ASCII encodings
        self.ui.dataEdit.setText(value.decode('ascii'))
        self.hide_output_offer()

    def hide_output_offer(self):
        self.output_offer.setPlainText("")
        self.output_offer.hide()
        self.output_offer_sell_hint.hide()
        self.output_offer_buy_hint.hide()

    def show_qr(self, tx_hex: str):
        tx = Transaction(tx_hex)
        qr_data = tx.to_qr_data()
        try:
            self.main_window.show_qrcode(qr_data, _('Buy Offer') if self.buy else _('Sell Offer'), parent=self)
        except qrcode.exceptions.DataOverflowError:
            self.show_error(_('Failed to display QR code.') + '\n' +
                            _('Offer is too large in size.'))
        except Exception as e:
            self.show_error(_('Failed to display QR code.') + '\n' + repr(e))

    def export_to_file(self, tx_hex: str):
        tx = Transaction(tx_hex)
        name = '{} Offer {} {} NMC'.format("Buy" if self.buy else "Sell", format_name_identifier(self.identifier), Decimal(self.amount_edit.get_amount()) / COIN)
        extension = 'txn'
        default_filter = TRANSACTION_FILE_EXTENSION_FILTER_ONLY_COMPLETE_TX
        name = f'{name}.{extension}'
        fileName = self.main_window.getSaveFileName(_("Select where to save your offer"),
                                                    name,
                                                    TRANSACTION_FILE_EXTENSION_FILTER_SEPARATE,
                                                    default_extension=extension,
                                                    default_filter=default_filter)
        if not fileName:
            return
        with open(fileName, "w+") as f:
            network_tx_hex = tx.serialize_to_network()
            f.write(network_tx_hex + '\n')

        self.show_message(_("Offer exported successfully"))
        self.saved = True

    def get_transfer_address(self, transfer_to):
        if transfer_to.toPlainText() == "":
            # User left the recipient blank, so this isn't a transfer.
            return None
        else:
            # The user entered something into the recipient text box.

            recipient_outputs = transfer_to.get_outputs(False)
            if recipient_outputs is None:
                return False
            if len(recipient_outputs) != 1:
                self.show_error(_("You must enter one transfer address, or leave the transfer field empty."))
                return False

            recipient_address = recipient_outputs[0].address
            if recipient_address is None:
                self.show_error(_("Invalid address ") + recipient_address)
                return False

            return recipient_address

    def trade(self, identifier, value, amount_sat, transfer_to, offer):
        if amount_sat is None:
            self.show_error(_("Amount is blank"))
            return
        amount = Decimal(amount_sat)/COIN

        recipient_address = self.get_transfer_address(transfer_to)
        if recipient_address == False:
            return

        name_buy = self.main_window.console.namespace.get('name_buy')
        name_sell = self.main_window.console.namespace.get('name_sell')
        broadcast = self.main_window.console.namespace.get('broadcast')

        offer = offer.replace(" ", "")

        if not is_hex_str(offer):
            if self.buy:
                self.show_error(_("Sell offer is not valid hex"))
            else:
                self.show_error(_("Buy offer is not valid hex"))
            return

        if offer == "":
            offer = None

        if offer is None and self.output_offer.toPlainText() != "":
            # Freeze input
            result_offer_tx = Transaction(self.output_offer.toPlainText())
            result_offer_input = result_offer_tx.inputs()[0]
            result_offer_address = self.wallet.get_txin_address(result_offer_input)
            self.wallet.set_frozen_state_of_addresses([result_offer_address], True)

            # Set label
            label = self.wallet.get_label(result_offer_address)
            if self.buy:
                label += _(" (reserved for Buy Offer: {})".format(format_name_identifier(identifier)))
            else:
                label += _(" (reserved for Sell Offer)")
            self.wallet.set_label(result_offer_address, label)

            self.accept()
            return

        if self.buy:
            error_message = _("Error buying {}: {}")
        else:
            error_message = _("Error selling {}: {}")

        try:
            if self.buy:
                # TODO: support non-ASCII encodings
                result = name_buy(identifier.decode('ascii'), value=value.decode('ascii'), amount=amount, destination=recipient_address, offer=offer)
            else:
                # TODO: support non-ASCII encodings
                result = name_sell(identifier.decode('ascii'), requested_amount=amount, offer=offer)
        except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
            formatted_name = format_name_identifier(identifier)
            self.show_error(error_message.format(formatted_name, str(e)))
            return
        except InternalAddressCorruption as e:
            formatted_name = format_name_identifier(identifier)
            self.show_error(error_message.format(formatted_name, str(e)))
            return
        except BestEffortRequestFailed as e:
            msg = repr(e)
            self.show_error(msg)
            return
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            formatted_name = format_name_identifier(identifier)
            self.show_error(error_message.format(formatted_name, str(e)))
            return

        if offer is None:
            self.output_offer.setPlainText(result)
            self.output_offer.show()
            if self.buy:
                self.output_offer_buy_hint.show()
                self.output_offer_sell_hint.hide()
            else:    
                self.output_offer_sell_hint.show()
                self.output_offer_buy_hint.hide()
        else:
            try:
                broadcast(result)
            except Exception as e:
                formatted_name = format_name_identifier(identifier)
                self.show_error(_("Error broadcasting trade for ") + formatted_name + ": " + str(e))
                return
            self.accept()
