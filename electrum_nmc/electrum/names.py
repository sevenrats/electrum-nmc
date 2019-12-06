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

def split_name_script(decoded):
    # This case happens if a script was malformed and couldn't be decoded by
    # transaction.get_address_from_output_script.
    if decoded is None:
        return {"name_op": None, "address_scriptPubKey": decoded}

    # name_new TxOuts look like:
    # NAME_NEW (hash) 2DROP (Bitcoin TxOut)
    match = [ OP_NAME_NEW, OPPushDataGeneric, opcodes.OP_2DROP ]
    if match_decoded(decoded[:len(match)], match):
        return {"name_op": {"op": OP_NAME_NEW, "hash": decoded[1][1]}, "address_scriptPubKey": decoded[len(match):]}

    # name_firstupdate TxOuts look like:
    # NAME_FIRSTUPDATE (name) (rand) (value) 2DROP 2DROP (Bitcoin TxOut)
    match = [ OP_NAME_FIRSTUPDATE, OPPushDataGeneric, OPPushDataGeneric, OPPushDataGeneric, opcodes.OP_2DROP, opcodes.OP_2DROP ]
    if match_decoded(decoded[:len(match)], match):
        return {"name_op": {"op": OP_NAME_FIRSTUPDATE, "name": decoded[1][1], "rand": decoded[2][1], "value": decoded[3][1]}, "address_scriptPubKey": decoded[len(match):]}

    # name_update TxOuts look like:
    # NAME_UPDATE (name) (value) 2DROP DROP (Bitcoin TxOut)
    match = [ OP_NAME_UPDATE, OPPushDataGeneric, OPPushDataGeneric, opcodes.OP_2DROP, opcodes.OP_DROP ]
    if match_decoded(decoded[:len(match)], match):
        return {"name_op": {"op": OP_NAME_UPDATE, "name": decoded[1][1], "value": decoded[2][1]}, "address_scriptPubKey": decoded[len(match):]}

    return {"name_op": None, "address_scriptPubKey": decoded}

def get_name_op_from_output_script(_bytes):
    try:
        decoded = [x for x in script_GetOp(_bytes)]
    except MalformedBitcoinScript:
        decoded = None

    # Extract the name script if one is present.
    return split_name_script(decoded)["name_op"]

def name_op_to_script(name_op):
    if name_op is None:
        script = ''
    elif name_op["op"] == OP_NAME_NEW:
        validate_new_length(name_op)
        script = '51'                                 # OP_NAME_NEW
        script += push_script(bh2u(name_op["hash"]))
        script += '6d'                                # OP_2DROP
    elif name_op["op"] == OP_NAME_FIRSTUPDATE:
        validate_firstupdate_length(name_op)
        script = '52'                                 # OP_NAME_FIRSTUPDATE
        script += push_script(bh2u(name_op["name"]))
        script += push_script(bh2u(name_op["rand"]))
        script += push_script(bh2u(name_op["value"]))
        script += '6d'                                # OP_2DROP
        script += '6d'                                # OP_2DROP
    elif name_op["op"] == OP_NAME_UPDATE:
        validate_update_length(name_op)
        script = '53'                                 # OP_NAME_UPDATE
        script += push_script(bh2u(name_op["name"]))
        script += push_script(bh2u(name_op["value"]))
        script += '6d'                                # OP_2DROP
        script += '75'                                # OP_DROP
    else:
        raise BitcoinException('unknown name op: {}'.format(name_op))
    return script

def validate_new_length(name_op):
    validate_hash_length(name_op["hash"])

def validate_firstupdate_length(name_op):
    validate_rand_length(name_op["rand"])
    validate_anyupdate_length(name_op)

def validate_update_length(name_op):
    validate_anyupdate_length(name_op)

def validate_anyupdate_length(name_op):
    validate_identifier_length(name_op["name"])
    validate_value_length(name_op["value"])

def validate_hash_length(commitment):
    hash_length_requirement = 20

    hash_length = len(commitment)
    if hash_length != hash_length_requirement:
        raise BitcoinException('hash length {} is not equal to requirement of {}'.format(hash_length, hash_length_requirement))

def validate_rand_length(rand):
    rand_length_requirement = 20

    rand_length = len(rand)
    if rand_length != rand_length_requirement:
        raise BitcoinException('rand length {} is not equal to requirement of {}'.format(rand_length, rand_length_requirement))

def validate_identifier_length(identifier):
    identifier_length_limit = 255

    identifier_length = len(identifier)
    if identifier_length > identifier_length_limit:
        raise BitcoinException('identifier length {} exceeds limit of {}'.format(identifier_length, identifier_length_limit))

def validate_value_length(value):
    value_length_limit = 520

    value_length = len(value)
    if value_length > value_length_limit:
        raise BitcoinException('value length {} exceeds limit of {}'.format(value_length, value_length_limit))

def build_name_new(identifier, rand = None):
    validate_identifier_length(identifier)

    if rand is None:
        rand = os.urandom(20)

    to_hash = rand + identifier
    commitment = hash_160(to_hash)

    return {"op": OP_NAME_NEW, "hash": commitment}, rand

def name_identifier_to_scripthash(identifier_bytes):
    name_op = {"op": OP_NAME_UPDATE, "name": identifier_bytes, "value": bytes([])}
    script = name_op_to_script(name_op)
    script += '6a' # OP_RETURN

    return script_to_scripthash(script)


def identifier_to_namespace(identifier_bytes):
    try:
        identifier = identifier_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None

    try:
        namespace, label = identifier.split("/", 1)
    except ValueError:
        return None

    if namespace == "d":
        if len(label) < 1:
            return None

        # Source: https://github.com/namecoin/proposals/blob/master/ifa-0001.md#keys
        if len(label) > 63:
            return None

        # Source: https://github.com/namecoin/proposals/blob/master/ifa-0001.md#keys
        label_regex = r"^(xn--)?[a-z0-9]+(-[a-z0-9]+)*$"
        label_match = re.match(label_regex, label)
        if label_match is None:
            return None

        # Reject digits-only labels
        number_regex = r"^[0-9]+$"
        number_match = re.match(number_regex, label)
        if number_match is not None:
            return None

        return namespace

    if namespace == "id":
        if len(label) < 1:
            return None

        # Max id/ identifier length is 255 chars according to wiki spec.  But we
        # don't need to check for this, because that's also the max length of an
        # identifier under the Namecoin consensus rules.

        # Same as d/ regex but without IDN prefix.
        # TODO: this doesn't exactly match the https://wiki.namecoin.org spec.
        label_regex = r"^[a-z0-9]+(-[a-z0-9]+)*$"
        label_match = re.match(label_regex, label)
        if label_match is None:
            return None

        return namespace

    return namespace

def format_name_identifier(identifier_bytes):
    try:
        identifier = identifier_bytes.decode("ascii")
    except UnicodeDecodeError:
        return format_name_identifier_unknown_hex(identifier_bytes)

    namespace = identifier_to_namespace(identifier_bytes)

    if namespace == "d":
        return format_name_identifier_domain(identifier)

    if namespace == "id":
        return format_name_identifier_identity(identifier)

    return format_name_identifier_unknown(identifier)


def format_name_identifier_domain(identifier):
    label = identifier[len("d/"):]

    return "Domain " + label + ".bit"


def format_name_identifier_identity(identifier):
    label = identifier[len("id/"):]

    return "Identity " + label

def format_name_identifier_unknown(identifier):
    # Check for non-printable characters, and print ASCII if none are found.
    if identifier.isprintable():
        return 'Non-standard name "' + identifier + '"'

    return format_name_identifier_unknown_hex(identifier.encode("ascii"))


def format_name_identifier_unknown_hex(identifier_bytes):
    return "Non-standard hex name " + bh2u(identifier_bytes)


def format_name_value(value_bytes):
    try:
        value = value_bytes.decode("ascii")
    except UnicodeDecodeError:
        return format_name_value_hex(value_bytes)

    if not value.isprintable():
        return format_name_value_hex(value_bytes)

    return "ASCII " + value


def format_name_value_hex(value_bytes):
    return "Hex " + bh2u(value_bytes)


def format_name_op(name_op):
    if name_op is None:
        return ''
    if "hash" in name_op:
        formatted_hash = "Commitment = " + bh2u(name_op["hash"])
    if "rand" in name_op:
        formatted_rand = "Salt = " + bh2u(name_op["rand"])
    if "name" in name_op:
        formatted_name = "Name = " + format_name_identifier(name_op["name"])
    if "value" in name_op:
        formatted_value = "Data = " + format_name_value(name_op["value"])

    if name_op["op"] == OP_NAME_NEW:
        return "\tPre-Registration\n\t\t" + formatted_hash
    if name_op["op"] == OP_NAME_FIRSTUPDATE:
        return "\tRegistration\n\t\t" + formatted_name + "\n\t\t" + formatted_rand + "\n\t\t" + formatted_value
    if name_op["op"] == OP_NAME_UPDATE:
        return "\tUpdate\n\t\t" + formatted_name + "\n\t\t" + formatted_value


def get_default_name_tx_label(wallet, tx):
    for idx, o in enumerate(tx.outputs()):
        name_op = o.name_op
        if name_op is not None:
            # TODO: Handle multiple atomic name ops.
            name_input_is_mine, name_output_is_mine, name_value_is_unchanged = get_wallet_name_delta(wallet, tx)
            if not name_input_is_mine and not name_output_is_mine:
                return None
            if name_input_is_mine and not name_output_is_mine:
                return "Transfer (Outgoing): " + format_name_identifier(name_op["name"])
            if not name_input_is_mine and name_output_is_mine:
                # A name_new transaction isn't expected to have a name input,
                # so we don't consider it a transfer.
                if name_op["op"] != OP_NAME_NEW:
                    return "Transfer (Incoming): " + format_name_identifier(name_op["name"])
            if name_op["op"] == OP_NAME_NEW:
                # Get the address where the NAME_NEW was sent to
                addr = o.address
                # Look for other transactions for this address, which might
                # include the NAME_FIRSTUPDATE
                addr_history = wallet.get_address_history(addr)
                for addr_txid, addr_height in addr_history:
                    # Examine a candidate tx that might be the NAME_FIRSTUPDATE
                    addr_tx = wallet.db.transactions.get(addr_txid)
                    # Look at all the candidate's inputs to make sure it's
                    # actually spending the NAME_NEW
                    for addr_tx_input in addr_tx.inputs():
                        if addr_tx_input['prevout_hash'] == tx.txid():
                            if addr_tx_input['prevout_n'] == idx:
                                # We've confirmed that it spends the NAME_NEW.
                                # Look at the outputs to find the
                                # NAME_FIRSTUPDATE.
                                for addr_tx_output in addr_tx.outputs():
                                    if addr_tx_output.name_op is not None:
                                        # We've found a name output; now we
                                        # check for an identifier.
                                        if 'name' in addr_tx_output.name_op:
                                            return "Pre-Registration: " + format_name_identifier(addr_tx_output.name_op['name'])

                # Look for queued transactions that spend the NAME_NEW
                addr_tx_output = get_queued_firstupdate_from_new(wallet, tx.txid(), idx)
                if addr_tx_output is not None:
                    return "Pre-Registration: " + format_name_identifier(addr_tx_output.name_op['name'])

                # A name_new transaction doesn't have a visible 'name' field,
                # so there's nothing to format if we can't find the name
                # elsewhere in the wallet.
                return "Pre-Registration"
            if name_op["op"] == OP_NAME_FIRSTUPDATE:
                return "Registration: " + format_name_identifier(name_op["name"])
            if name_op["op"] == OP_NAME_UPDATE:
                if name_value_is_unchanged:
                    return "Renew: " + format_name_identifier(name_op["name"])
                else:
                    return "Update: " + format_name_identifier(name_op["name"])
    return None


def get_queued_firstupdate_from_new(wallet, txid, idx):
    # Look for queued transactions that spend the NAME_NEW
    for addr_txid in wallet.db.queued_transactions:
        addr_tx_queue_item = wallet.db.queued_transactions[addr_txid]
        # Check whether the queued transaction is contingent on the NAME_NEW transaction
        if addr_tx_queue_item['sendWhen']['txid'] == txid:
            addr_tx = Transaction(addr_tx_queue_item['tx'])
            # Look at all the candidate's inputs to make sure it's
            # actually spending the NAME_NEW
            for addr_tx_input in addr_tx.inputs():
                if addr_tx_input['prevout_hash'] == txid:
                    if addr_tx_input['prevout_n'] == idx:
                        # We've confirmed that it spends the NAME_NEW.
                        # Look at the outputs to find the
                        # NAME_FIRSTUPDATE.
                        for addr_tx_output in addr_tx.outputs():
                            if addr_tx_output.name_op is not None:
                                # We've found a name output; now we
                                # check for an identifier.
                                if 'name' in addr_tx_output.name_op:
                                    return addr_tx_output
    return None


def get_wallet_name_delta(wallet, tx):
    name_input_is_mine = False
    name_output_is_mine = False

    name_input_value = None
    name_output_value = None

    for txin in tx.inputs():
        addr = wallet.get_txin_address(txin)
        if wallet.is_mine(addr):
            prev_tx = wallet.db.transactions.get(txin['prevout_hash'])
            if prev_tx.outputs()[txin['prevout_n']].name_op is not None:
                name_input_is_mine = True
                if 'value' in prev_tx.outputs()[txin['prevout_n']].name_op:
                    name_input_value = prev_tx.outputs()[txin['prevout_n']].name_op['value']
    for o in tx.outputs():
        if o.name_op is not None and wallet.is_mine(o.address):
            name_output_is_mine = True
            if 'value' in o.name_op:
                name_output_value = o.name_op['value']

    name_value_is_unchanged = name_input_value == name_output_value

    return name_input_is_mine, name_output_is_mine, name_value_is_unchanged


def get_wallet_name_count(wallet, network):
    confirmed_count = 0
    pending_count = 0

    utxos = wallet.get_utxos()
    for _, x in enumerate(utxos):
        txid = x.get('prevout_hash')
        vout = x.get('prevout_n')
        name_op = wallet.db.transactions[txid].outputs()[vout].name_op
        if name_op is None:
            continue
        height = x.get('height')
        chain_height = network.blockchain().height()
        expires_in = name_expires_in(height, chain_height)
        if expires_in is None:
            # Transaction isn't mined yet
            if name_op['op'] in [OP_NAME_NEW, OP_NAME_FIRSTUPDATE]:
                # Registration is pending
                pending_count += 1
                continue
            else:
                # name_update is pending
                # TODO: we shouldn't consider it confirmed if it's an incoming
                # or outgoing transfer.
                confirmed_count += 1
                continue
        if expires_in <= 0:
            # Expired
            continue
        if 'name' in name_op:
            # name_anyupdate is mined (not expired)
            confirmed_count += 1
            continue
        else:
            # name_new is mined
            pending_count += 1
            continue
    return confirmed_count, pending_count


def name_expires_in(name_height, chain_height):
    if name_height <= 0:
        return None

    return name_height - chain_height + 36000


def name_expiration_datetime_estimate(name_height, chain_height, chain_unixtime):
    expiration_blocks = name_expires_in(name_height, chain_height)

    if expiration_blocks is None:
        return None, None

    block_timedelta = timedelta(minutes=10)
    expiration_timedelta = expiration_blocks * block_timedelta
    chain_datetime = datetime.fromtimestamp(chain_unixtime)
    return expiration_blocks, chain_datetime + expiration_timedelta

def get_domain_records(domain, value):
    if type(value) == bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return [], value

    if type(value) == str:
        if value == "":
            value = "{}"

        try:
            value = json.loads(value)
        except json.decoder.JSONDecodeError:
            return [], value

    if type(value) != dict:
        return [], value

    records = []

    new_records, value = get_domain_records_address(domain, value)
    records.extend(new_records)

    if "alias" in value:
        new_records, value["alias"] = get_domain_records_cname(domain, value["alias"])
        records.extend(new_records)
        if value["alias"] == None:
            del value["alias"]

    if "ns" in value:
        new_records, value["ns"] = get_domain_records_ns(domain, value["ns"])
        records.extend(new_records)
        if value["ns"] == []:
            del value["ns"]

    if "ds" in value:
        new_records, value["ds"] = get_domain_records_ds(domain, value["ds"])
        records.extend(new_records)
        if value["ds"] == []:
            del value["ds"]

    if "tls" in value:
        new_records, value["tls"] = get_domain_records_tls(domain, value["tls"])
        records.extend(new_records)
        if value["tls"] == []:
            del value["tls"]

    if "sshfp" in value:
        new_records, value["sshfp"] = get_domain_records_sshfp(domain, value["sshfp"])
        records.extend(new_records)
        if value["sshfp"] == []:
            del value["sshfp"]

    if "txt" in value:
        new_records, value["txt"] = get_domain_records_txt(domain, value["txt"])
        records.extend(new_records)
        if value["txt"] == []:
            del value["txt"]

    if "srv" in value:
        new_records, value["srv"] = get_domain_records_srv(domain, value["srv"])
        records.extend(new_records)
        if value["srv"] == []:
            del value["srv"]

    if "map" in value:
        new_records, value["map"] = get_domain_records_map(domain, value["map"])
        records.extend(new_records)
        if value["map"] == {}:
            del value["map"]

    return records, value

def get_domain_records_address(domain, value):
    records = []

    if "ip" in value:
        new_records, value["ip"] = get_domain_records_address_ip4(domain, value["ip"])
        records.extend(new_records)
        if value["ip"] == []:
            del value["ip"]

    if "ip6" in value:
        new_records, value["ip6"] = get_domain_records_address_ip6(domain, value["ip6"])
        records.extend(new_records)
        if value["ip6"] == []:
            del value["ip6"]

    if "tor" in value:
        new_records, value["tor"] = get_domain_records_address_tor(domain, value["tor"])
        records.extend(new_records)
        if value["tor"] == []:
            del value["tor"]

    if "i2p" in value:
        new_records, value["i2p"] = get_domain_records_address_i2p(domain, value["i2p"])
        records.extend(new_records)
        if value["i2p"] == []:
            del value["i2p"]

    if "freenet" in value:
        new_records, value["freenet"] = get_domain_records_address_freenet(domain, value["freenet"])
        records.extend(new_records)
        if value["freenet"] == None:
            del value["freenet"]

    if "zeronet" in value:
        new_records, value["zeronet"] = get_domain_records_address_zeronet(domain, value["zeronet"])
        records.extend(new_records)
        if value["zeronet"] == None:
            del value["zeronet"]

    return records, value

def get_domain_records_address_ip4(domain, value):
    # Convert string to array (only 1 A record exists)
    if type(value) == str:
        value = [value]

    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_address_ip4_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_address_ip4_single(domain, value):
    # Must be string
    if type(value) != str:
        return None, value

    return [domain, "address", ["ip4", value]], None

def get_domain_records_address_ip6(domain, value):
    # Convert string to array (only 1 AAAA record exists)
    if type(value) == str:
        value = [value]

    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_address_ip6_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_address_ip6_single(domain, value):
    # Must be string
    if type(value) != str:
        return None, value

    return [domain, "address", ["ip6", value]], None

def get_domain_records_address_tor(domain, value):
    # Convert string to array (only 1 Tor record exists)
    if type(value) == str:
        value = [value]

    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_address_tor_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_address_tor_single(domain, value):
    # Must be string
    if type(value) != str:
        return None, value

    return [domain, "address", ["tor", value]], None

def get_domain_records_address_i2p(domain, value):
    # Convert string to array (only 1 I2P record exists)
    if type(value) == str:
        value = [value]

    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_address_i2p_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_address_i2p_single(domain, value):
    # Must be string
    if type(value) != str:
        return None, value

    return [domain, "address", ["i2p", value]], None

def get_domain_records_address_freenet(domain, value):
    records = []
    remaining = None

    # Must be string
    if type(value) != str:
        return [], value

    records.append([domain, "address", ["freenet", value]])

    return records, remaining

def get_domain_records_address_zeronet(domain, value):
    records = []
    remaining = None

    # Parse the standards-compliant ZeroNet format
    if type(value) == str:
        records.append([domain, "address", ["zeronet", value]])

    # Parse the old-style dict ZeroNet format
    if type(value) == dict:
        for label in value:
            # Make sure the ZeroNet value is a string, bail if it's not
            if type(value[label]) != str:
                return [], value

            # Special-case for empty ZeroNet key
            if label == "":
                single_domain = domain
            else:
                single_domain = label + "." + domain

            records.append([single_domain, "address", ["zeronet", value[label]]])

    return records, remaining

def get_domain_records_cname(domain, value):
    records = []
    remaining = None

    # Must be string
    if type(value) != str:
        return [], value

    records.append([domain, "cname", value])

    return records, remaining

def get_domain_records_ns(domain, value):
    # Convert string to array (only 1 NS record exists)
    if type(value) == str:
        value = [value]
    
    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_ns_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_ns_single(domain, value):
    # Must be string
    if type(value) != str:
        return None, value

    return [domain, "ns", value], None

def get_domain_records_ds(domain, value):
    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_ds_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_ds_single(domain, value):
    # Must be array
    if type(value) != list:
        return None, value

    # Must be length 4
    if len(value) != 4:
        return None, value

    # Check value types
    if type(value[0]) != int or type(value[1]) != int or type(value[2]) != int or type(value[3]) != str:
        return None, value

    return [domain, "ds", value], None

def get_domain_records_tls(domain, value):
    # Handle TLS subdomain
    try:
        port, protocol, domain = domain.split(".", 2)
        port = port[1:]
        protocol = protocol[1:]
    except IndexError:
        return [], value

    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_tls_single(domain, raw_address, protocol, port)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_tls_single(domain, value, protocol, port):
    # Port must be an integer
    try:
        port = int(port)
    except ValueError:
        return None, value

    # Convert array to dict (default DANE format)
    if type(value) == list:
        value = {"dane": value}

    # Must be dict
    if type(value) != dict:
        return None, value

    # Technically a TLS object can have both Dehydrated and DANE versions at once.
    # This is unusual and we don't try to handle this.
    if len(value) != 1:
        return None, value

    # Check format
    if "dane" in value:
        cert = value["dane"]
        if type(cert) != list:
            return None, value
        if len(cert) != 4:
            return None, value
        if type(cert[0]) != int or type(cert[1]) != int or type(cert[2]) != int or type(cert[3]) != str:
            return None, value
    # TODO: enable Dehydrated format by uncommenting the below code.  We need
    # to finish the GUI first.
    #elif "d8" in value:
    #    cert = value["d8"]
    #    if type(cert) != list:
    #        return None, value
    #    if len(cert) != 6:
    #        return None, value
    #    if cert[0] != 1:
    #        return None, value
    #    if type(cert[1]) != str or type(cert[2]) != int or type(cert[3]) != int or type(cert[4]) != int or type(cert[5]) != str:
    #        return None, value
    else:
        return None, value

    return [domain, "tls", [protocol, port, value]], None

def get_domain_records_sshfp(domain, value):
    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_sshfp_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_sshfp_single(domain, value):
    # Must be array
    if type(value) != list:
        return None, value

    # Must be length 3
    if len(value) != 3:
        return None, value

    # Check value types
    if type(value[0]) != int or type(value[1]) != int or type(value[2]) != str:
        return None, value

    return [domain, "sshfp", value], None

def get_domain_records_txt(domain, value):
    # Process Tor specially
    if domain.startswith("_tor."):
        domain = domain[len("_tor."):]
        return get_domain_records_address_tor(domain, value)

    # Convert string to array (only 1 TXT record exists)
    if type(value) == str:
        value = [value]

    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_txt_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_txt_single(domain, value):
    # Must be string
    if type(value) != str:
        return None, value

    # TODO: Handle TXT records that are an array.

    return [domain, "txt", value], None

def get_domain_records_srv(domain, value):
    # Must be array
    if type(value) != list:
        return [], value

    # Parse each array item
    records = []
    remaining = []
    for raw_address in value:
        single_record, single_remaining = get_domain_records_srv_single(domain, raw_address)
        if single_record is not None:
            records.append(single_record)
        if single_remaining is not None:
            remaining.append(single_remaining)

    return records, remaining

def get_domain_records_srv_single(domain, value):
    # Must be array
    if type(value) != list:
        return None, value

    # Must be length 4
    if len(value) != 4:
        return None, value

    # Check value types
    if type(value[0]) != int or type(value[1]) != int or type(value[2]) != int or type(value[3]) != str:
        return None, value

    return [domain, "srv", value], None

def get_domain_records_map(domain, value):
    # Must be dict
    if type(value) != dict:
        return [], value

    # Parse each dict item
    records = []
    remaining = {}
    for subdomain in value:
        # Special form where map key is empty
        if subdomain == "":
            # This special form is a security hazard and should be avoided.  We
            # therefore don't parse it.  If you want to parse it, uncomment the
            # next line, and comment out the "continue".
            #single_domain = domain
            continue
        else:
            single_domain = subdomain + "." + domain

        # Special form where a map value is a string
        single_value = value[subdomain]
        if type(single_value) == str:
            single_value = {"ip": single_value}

        new_records, remaining[subdomain] = get_domain_records(single_domain, single_value)

        records.extend(new_records)
        if remaining[subdomain] == {}:
            del remaining[subdomain]

    return records, remaining

def add_domain_record(base_domain, value, record):
    domain, record_type, data = record

    # Handle Tor records specially
    if record_type == "address" and data[0] == "tor":
        domain = "_tor." + domain
        record_type = "txt"
        data = data[1]

    # Handle TLS record specially to prepend protocol/port subdomain
    if record_type == "tls":
        protocol, port, data = data
        domain = "_" + str(port) + "._" + protocol + "." + domain

    if not domain.endswith(base_domain):
        raise Exception("Base domain mismatch")

    if domain == base_domain:
        map_labels = []
    else:
        subdomain = domain[:-len("." + base_domain)]
        map_labels = subdomain.split(".")[::-1]

    add_domain_record_map(value, map_labels)

    # Traverse the "map" field until we arrive at the subdomain we want
    subdomain_value = value
    for label in map_labels:
        subdomain_value = subdomain_value["map"][label]

    if record_type == "address":
        add_domain_record_address(subdomain_value, data)
    elif record_type == "cname":
        add_domain_record_cname(subdomain_value, data)
    elif record_type == "ns":
        add_domain_record_ns(subdomain_value, data)
    elif record_type == "ds":
        add_domain_record_ds(subdomain_value, data)
    elif record_type == "tls":
        add_domain_record_tls(subdomain_value, data)
    elif record_type == "sshfp":
        add_domain_record_sshfp(subdomain_value, data)
    elif record_type == "txt":
        add_domain_record_txt(subdomain_value, data)
    elif record_type == "srv":
        add_domain_record_srv(subdomain_value, data)

def add_domain_record_map(value, map_labels):
    if len(map_labels) == 0:
        return

    # Make sure the map field exists
    if "map" not in value:
        value["map"] = {}

    # Make sure the subdomain exists
    if map_labels[0] not in value["map"]:
        value["map"][map_labels[0]] = {}

    # Move onto the next map label
    add_domain_record_map(value["map"][map_labels[0]], map_labels[1:])

def add_domain_record_address(value, data):
    address_type, address_data = data
    if address_type == "ip4":
        add_domain_record_address_ip4(value, address_data)
    elif address_type == "ip6":
        add_domain_record_address_ip6(value, address_data)
    elif address_type == "i2p":
        add_domain_record_address_i2p(value, address_data)
    elif address_type == "freenet":
        add_domain_record_address_freenet(value, address_data)
    elif address_type == "zeronet":
        add_domain_record_address_zeronet(value, address_data)
    else:
        raise Exception("Unknown address type")

def add_domain_record_address_ip4(value, data):
    # Make sure the field exists
    if "ip" not in value:
        value["ip"] = []

    # Make sure the field is an array
    if type(value["ip"]) == str:
        value["ip"] = [value["ip"]]

    # Add the record
    value["ip"].append(data)

    # Minimize to string form if possible
    if len(value["ip"]) == 1:
        value["ip"] = value["ip"][0]

def add_domain_record_address_ip6(value, data):
    # Make sure the field exists
    if "ip6" not in value:
        value["ip6"] = []

    # Add the record
    value["ip6"].append(data)

def add_domain_record_address_i2p(value, data):
    # Make sure the field exists
    if "i2p" not in value:
        value["i2p"] = []

    # Add the record
    value["i2p"].append(data)

def add_domain_record_address_freenet(value, data):
    # Make sure the field doesn't already exist
    if "freenet" in value:
        raise Exception("Multiple Freenet records for one domain")

    # Add the record
    value["freenet"] = data

def add_domain_record_address_zeronet(value, data):
    # Make sure the field doesn't already exist
    if "zeronet" in value:
        raise Exception("Multiple ZeroNet records for one domain")

    # Add the record
    value["zeronet"] = data

def add_domain_record_cname(value, data):
    # Make sure the field doesn't already exist
    if "alias" in value:
        raise Exception("Multiple CNAME records for one domain")

    # Add the record
    value["alias"] = data

def add_domain_record_ns(value, data):
    # Make sure the field exists
    if "ns" not in value:
        value["ns"] = []

    # Add the record
    value["ns"].append(data)

def add_domain_record_ds(value, data):
    # Make sure the field exists
    if "ds" not in value:
        value["ds"] = []

    # Add the record
    value["ds"].append(data)

def add_domain_record_tls(value, data):
    # Make sure the field exists
    if "tls" not in value:
        value["tls"] = []

    # Minimize the DANE format
    if "dane" in data:
        data = data["dane"]

    # Add the record
    value["tls"].append(data)

def add_domain_record_sshfp(value, data):
    # Make sure the field exists
    if "sshfp" not in value:
        value["sshfp"] = []

    # Add the record
    value["sshfp"].append(data)

def add_domain_record_txt(value, data):
    # Make sure the field exists
    if "txt" not in value:
        value["txt"] = []

    # Add the record
    value["txt"].append(data)

def add_domain_record_srv(value, data):
    # Make sure the field exists
    if "srv" not in value:
        value["srv"] = []

    # Add the record
    value["srv"].append(data)


import binascii
from datetime import datetime, timedelta
import json
import os
import re

from .bitcoin import push_script, script_to_scripthash
from .crypto import hash_160
from .transaction import MalformedBitcoinScript, match_decoded, opcodes, OPPushDataGeneric, script_GetOp, Transaction
from .util import bh2u, BitcoinException

OP_NAME_NEW = opcodes.OP_1
OP_NAME_FIRSTUPDATE = opcodes.OP_2
OP_NAME_UPDATE = opcodes.OP_3

