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
from .util import MessageBoxMixin

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_configure_dns(value, parent):
    if value != b"":
        try:
            json.loads(value)
        except json.decoder.JSONDecodeError:
            parent.show_error(_("Current value of name is not valid JSON; please fix this before using the DNS editor."))
            return

    d = ConfigureDNSDialog(value, parent)

    dialogs.append(d)
    d.show()

class ConfigureDNSDialog(QDialog, MessageBoxMixin):
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
        self.ui.btnCNAMECreate.clicked.connect(self.create_cname_record)
        self.ui.btnNSCreate.clicked.connect(self.create_ns_record)
        self.ui.btnDSCreate.clicked.connect(self.create_ds_record)
        self.ui.btnTLSCreate.clicked.connect(self.create_tls_record)
        self.ui.btnSSHFPCreate.clicked.connect(self.create_sshfp_record)
        self.ui.btnTXTCreate.clicked.connect(self.create_txt_record)
        self.ui.btnSRVCreate.clicked.connect(self.create_srv_record)

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
            "I2P": "i2p",
            "Freenet": "freenet",
            "ZeroNet": "zeronet",
        }

        address_type = address_type_dict[self.ui.comboHostType.currentText()]

        if address_type == "freenet" and self.has_freenet_record(domain):
            self.show_error(domain + _(" already has a Freenet record."))
            return

        if address_type == "zeronet" and self.has_zeronet_record(domain):
            self.show_error(domain + _(" already has a ZeroNet record."))
            return

        address = self.ui.editAHostname.text()

        record = [domain, "address", [address_type, address]]

        self.insert_record(idx, record)

    def create_cname_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()

        if self.has_cname_record(domain):
            self.show_error(domain + _(" already has a CNAME record."))
            return

        data = self.ui.editCNAMEAlias.text()

        record = [domain, "cname", data]

        self.insert_record(idx, record)

    def create_ns_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        data = self.ui.editNSHosts.text()

        record = [domain, "ns", data]

        self.insert_record(idx, record)

    def create_ds_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        try:
            data = [
                int(self.ui.editDSKeyTag.text()),
                int(self.ui.editDSAlgorithm.text()),
                int(self.ui.editDSHashType.text()),
                self.ui.editDSHash.text(),
            ]
        except ValueError:
            self.show_error(_("The Keytag, Algorithm, and Hashtype must be integers."))
            return

        record = [domain, "ds", data]

        self.insert_record(idx, record)

    def create_tls_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        try:
            tls = [
                int(self.ui.editTLSCertUsage.text()),
                int(self.ui.editTLSSelector.text()),
                int(self.ui.editTLSMatchingType.text()),
                self.ui.editTLSData.toPlainText(),
            ]
        except ValueError:
            self.show_error(_("The Cert Usage, Selector, and Matching Type must be integers."))
            return
        try:
            data = [
                self.ui.editTLSProto.text(),
                int(self.ui.editTLSPort.text()),
                tls,
            ]
        except ValueError:
            self.show_error(_("The Port must be an integer."))
            return

        record = [domain, "tls", data]

        self.insert_record(idx, record)

    def create_sshfp_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        try:
            data = [
                int(self.ui.editSSHFPAlgorithm.text()),
                int(self.ui.editSSHFPFingerprintType.text()),
                self.ui.editSSHFPFingerprint.text(),
            ]
        except ValueError:
            self.show_error(_("The Algorithm and Fingerprint Type must be integers."))
            return

        record = [domain, "sshfp", data]

        self.insert_record(idx, record)

    def create_txt_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        data = self.ui.editTXTData.text()

        record = [domain, "txt", data]

        self.insert_record(idx, record)

    def create_srv_record(self):
        model = self.ui.listDNSRecords.model()
        idx = model.rowCount()

        domain = self.get_selected_domain()
        try:
            data = [
                int(self.ui.editSRVPriority.text()),
                int(self.ui.editSRVWeight.text()),
                int(self.ui.editSRVPort.text()),
                self.ui.editSRVHost.text(),
            ]
        except ValueError:
            self.show_error(_("The Priority, Weight, and Port must be integers."))
            return

        record = [domain, "srv", data]

        self.insert_record(idx, record)

    def has_freenet_record(self, domain):
        for record in self.get_records():
            record_domain, record_type, data = record

            if record_domain == domain and record_type == "address" and data[0] == "freenet":
                return True

        return False

    def has_zeronet_record(self, domain):
        for record in self.get_records():
            record_domain, record_type, data = record

            if record_domain == domain and record_type == "address" and data[0] == "zeronet":
                return True

        return False

    def has_cname_record(self, domain):
        for record in self.get_records():
            record_domain, record_type, data = record

            if record_domain == domain and record_type == "cname":
                return True

        return False

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
            elif data[0] == "i2p":
                formatted_data = "I2P: " + data[1]
            elif data[0] == "freenet":
                formatted_data = "Freenet: " + data[1]
            elif data[0] == "zeronet":
                formatted_data = "ZeroNet: " + data[1]
            else:
                raise Exception("Unknown address type")
        elif record_type == "cname":
            formatted_record_type = "CNAME"
            formatted_data = data
        elif record_type == "ns":
            formatted_record_type = "NS"
            formatted_data = data
        elif record_type == "ds":
            formatted_record_type = "DS"
            formatted_data = json.dumps(data)
        elif record_type == "tls":
            formatted_record_type = "TLS"
            formatted_data = json.dumps(data)
        elif record_type == "sshfp":
            formatted_record_type = "SSHFP"
            formatted_data = json.dumps(data)
        elif record_type == "txt":
            formatted_record_type = "TXT"
            formatted_data = json.dumps(data)
        elif record_type == "srv":
            formatted_record_type = "SRV"
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

