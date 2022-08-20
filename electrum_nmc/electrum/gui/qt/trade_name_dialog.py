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
from electrum.names import format_name_identifier, format_name_identifier_split
from electrum.network import TxBroadcastError, BestEffortRequestFailed
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, is_hex_str
from electrum.wallet import InternalAddressCorruption

from .forms.tradenamedialog import Ui_TradeNameDialog
from .amountedit import AmountEdit, BTCAmountEdit
from .util import MessageBoxMixin

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

        self.ui.buttonBox.accepted.connect(lambda: self.trade(self.identifier, self.amount_edit.get_amount(), self.input_offer.toPlainText()))

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

        self.input_offer = self.ui.inputOffer
        self.submit_sell_hint = self.ui.labelSubmitSellHint
        self.submit_buy_hint = self.ui.labelSubmitBuyHint
        if buy:
            self.submit_sell_hint.hide()
            self.submit_buy_hint.show()
        else:
            self.submit_sell_hint.show()
            self.submit_buy_hint.hide()

        self.output_offer = self.ui.outputOffer
        self.output_offer_sell_hint = self.ui.labelOutputSellHint
        self.output_offer_buy_hint = self.ui.labelOutputBuyHint
        self.hide_output_offer()

        self.amount_edit.textChanged.connect(self.hide_output_offer)
        self.input_offer.textChanged.connect(self.hide_output_offer)

    def hide_output_offer(self):
        self.output_offer.setPlainText("")
        self.output_offer.hide()
        self.output_offer_sell_hint.hide()
        self.output_offer_buy_hint.hide()

    def trade(self, identifier, amount_sat, offer):
        if amount_sat is None:
            self.show_error(_("Amount is blank"))
            return
        amount = Decimal(amount_sat)/COIN

        if self.buy:
            name_trade = self.main_window.console.namespace.get('name_buy')
        else:
            name_trade = self.main_window.console.namespace.get('name_sell')
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
            return

        if self.buy:
            error_message = _("Error buying {}: {}")
        else:
            error_message = _("Error selling {}: {}")

        try:
            # TODO: support non-ASCII encodings
            result = name_trade(identifier.decode('ascii'), amount=amount, offer=offer)
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
