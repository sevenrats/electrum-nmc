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

from copy import deepcopy
from enum import IntEnum
import json
import sys
import traceback
from typing import Union, List, Dict

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electrum.i18n import _
from electrum.names import add_domain_record, get_domain_records

from .forms.dnsdialog import Ui_DNSDialog

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_configure_dns(value, parent):
    d = ConfigureDNSDialog(value, parent)

    dialogs.append(d)
    d.show()

class ConfigureDNSDialog(QDialog):
    class Columns(IntEnum):
        DOMAIN = 0
        TYPE = 1
        DATA = 2

    headers = {
        Columns.DOMAIN: _('Domain'),
        Columns.TYPE: _('Type'),
        Columns.DATA: _('Data'),
    }

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

        subdomains = set([self.base_domain])

        records, self.extra_records = get_domain_records(self.base_domain, value)

        subdomains.update([record[0] for record in records])

        self.ui.comboDomain.addItems(list(subdomains))

        self.ui.listDNSRecords.setModel(QStandardItemModel(self))
        self.ui.listDNSRecords.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.ui.listDNSRecords.setSortingEnabled(True)

        self.ui.listDNSRecords.model().clear()
        self.update_headers(self.__class__.headers)

        # Update byte usage at least once in case there aren't any records to
        # add.
        self.update_byte_usage()

        for idx, record in enumerate(records):
            self.insert_record(idx, record)

        self.ui.btnACreate.clicked.connect(self.create_address_record)
        self.ui.btnTXTCreate.clicked.connect(self.create_txt_record)

        self.ui.dialogButtons.accepted.connect(self.accept)
        self.ui.dialogButtons.rejected.connect(self.reject)

        self.accepted.connect(lambda: self.name_dialog.set_value(self.get_value()))

    def get_selected_domain(self):
        return self.ui.comboDomain.currentText()

    def create_address_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        address_type_dict = {
            "IPv4": "ip4",
            "IPv6": "ip6",
            "Tor": "tor",
        }
        address_type = address_type_dict[self.ui.comboHostType.currentText()]
        address = self.ui.editAHostname.text()

        record = [domain, "address", [address_type, address]]

        self.insert_record(idx, record)

    def create_txt_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        data = self.ui.editTXTData.text()

        record = [domain, "txt", data]

        self.insert_record(idx, record)

    def insert_record(self, idx, record):
        domain, record_type, data = record

        formatted_domain = domain

        if record_type == "address":
            formatted_record_type = "Address"
            if data[0] == "ip4":
                formatted_data = "IPv4: " + data[1]
            elif data[0] == "ip6":
                formatted_data = "IPv6: " + data[1]
            elif data[0] == "tor":
                formatted_data = "Tor: " + data[1]
            else:
                raise Exception("Unknown address type")
        elif record_type == "txt":
            formatted_record_type = "TXT"
            formatted_data = json.dumps(data)
        else:
            raise Exception("Unknown record type")

        labels = [formatted_domain, formatted_record_type, formatted_data]
        record_item = [QStandardItem(x) for x in labels]

        record_item[self.Columns.DOMAIN].setData(domain, Qt.UserRole)
        record_item[self.Columns.TYPE].setData(record_type, Qt.UserRole)
        record_item[self.Columns.DATA].setData(data, Qt.UserRole)

        for cell in record_item:
            cell.setEditable(False)

        self.ui.listDNSRecords.model().insertRow(idx, record_item)

        self.update_byte_usage()

    def get_records(self):
        model = self.ui.listDNSRecords.model()

        records = []

        # Iterate through all rows in the table
        for row in range(model.rowCount()):
            # Get the indexes for each cell in the row
            row_indexes = [model.index(row, column) for column in range(model.columnCount())]

            # Extract the data from each cell in the row
            single_record = list([model.data(index, Qt.UserRole) for index in row_indexes])

            records.append(single_record)

        return records

    def get_value(self):
        value = deepcopy(self.extra_records)

        for record in self.get_records():
            add_domain_record(self.base_domain, value, record)

        if value == {}:
            return b""
        else:
            return json.dumps(value).encode("ascii")

    def update_headers(self, headers: Union[List[str], Dict[int, str]]):
        # headers is either a list of column names, or a dict: (col_idx->col_name)
        if not isinstance(headers, dict):  # convert to dict
            headers = dict(enumerate(headers))
        col_names = [headers[col_idx] for col_idx in sorted(headers.keys())]
        model = self.ui.listDNSRecords.model()
        model.setHorizontalHeaderLabels(col_names)

    def update_byte_usage(self):
        value = self.get_value()
        usage = len(value)
        usage_text = str(usage)

        label = self.ui.labelBytes
        label.setText(usage_text)

