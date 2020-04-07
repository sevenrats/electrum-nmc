Electrum-NMC - Lightweight Namecoin client
=====================================

::

  Licence: GNU GPLv3+ for Electrum-DOGE components; CC BY 4.0 for Namecoin logo, MIT Licence for all other components
  Author: The Namecoin developers; based on Electrum by Thomas Voegtlin and Electrum-DOGE by The Electrum-DOGE contributors
  Language: Python (>= 3.6)
  Homepage: https://www.namecoin.org/ ; original Electrum Homepage at https://electrum.org/


.. image:: https://travis-ci.org/namecoin/electrum-nmc.svg?branch=master
    :target: https://travis-ci.org/namecoin/electrum-nmc
    :alt: Build Status
.. image:: https://coveralls.io/repos/github/namecoin/electrum-nmc/badge.svg?branch=master
    :target: https://coveralls.io/github/namecoin/electrum-nmc?branch=master
    :alt: Test coverage statistics
.. image:: https://d322cqt584bo4o.cloudfront.net/electrum/localized.svg
    :target: https://crowdin.com/project/electrum
    :alt: Help translate Electrum online





Getting started
===============

Electrum-NMC is a pure python application. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

If you downloaded the official package (tar.gz), you can run
Electrum-NMC from its root directory without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electrum-NMC from its root directory, just do::

    ./run_electrum_nmc

You can also install Electrum-NMC on your system, by running this command::

    sudo apt-get install python3-setuptools
    python3 -m pip install .[fast]

This will download and install the Python dependencies used by
Electrum-NMC instead of using the 'packages' directory.
The 'fast' extra contains some optional dependencies that we think
are often useful but they are not strictly needed.

If you cloned the git repository, you need to compile extra files
before you can run Electrum-NMC. Read the next section, "Development
Version".



Development version
===================

Check out the code from GitHub::

    git clone git://github.com/namecoin/electrum-nmc.git
    cd electrum-nmc

Run install (this should install dependencies)::

    python3 -m pip install .[fast]


Compile the Qt UI::

    sudo apt-get install pyqt5-dev-tools
    ./contrib/make_qt_forms

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=electrum_nmc/electrum --python_out=electrum_nmc/electrum electrum_nmc/electrum/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/pull_locale




Creating Binaries
=================

Linux (tarball)
---------------

See :code:`contrib/build-linux/README.md`.


Linux (AppImage)
----------------

See :code:`contrib/build-linux/appimage/README.md`.


Mac OS X / macOS
----------------

See :code:`contrib/osx/README.md`.


Windows
-------

See :code:`contrib/build-wine/README.md`.


Android
-------

See :code:`electrum_nmc/electrum/gui/kivy/Readme.md`.



AuxPoW Branch
=============

Electrum-NMC also maintains an ``auxpow`` branch.  This branch is identical to the upstream Bitcoin version of Electrum (e.g. it doesn't have any name support or Namecoin rebranding), except that it supports AuxPoW (merged mining).  It may be useful as a starting point for porting Electrum to other AuxPoW-based cryptocurrencies.
