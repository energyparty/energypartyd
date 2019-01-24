# Copyright (c) 2016-Present Energyparty Developers
# Distributed under the AGPL 3.0 with the OpenSSL exception, see the
# accompanying file LICENSE or <https://github.com/energyparty/energypartyd/>.

import lib.bitcoin

def check():
    return True

def searchrawtransactions(address):
    return lib.bitcoin.rpc('searchrawtransactions', [address, 1, 0, 9999999])
