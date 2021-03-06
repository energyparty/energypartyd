# Copyright (c) 2016-Present Energyparty Developers
# Distributed under the AGPL 3.0 with the OpenSSL exception, see the
# accompanying file LICENSE or <https://github.com/energyparty/energypartyd/>.

import sys
import os

UNIT = 1000000


# Versions
VERSION_MAJOR = 9
VERSION_MINOR = 55
VERSION_REVISION = 0
VERSION_STRING = str(VERSION_MAJOR) + '.' + str(VERSION_MINOR) + '.' + str(VERSION_REVISION)

TXTYPE_FORMAT = '>I'

TWO_WEEKS = 2 * 7 * 24 * 3600
MAX_EXPIRATION = 60 * 576

MEMPOOL_BLOCK_HASH = 'mempool'
MEMPOOL_BLOCK_INDEX = 9999999


# SQLite3
MAX_INT = 2**63 - 1

OP_RETURN_MAX_SIZE = 80


# Currency agnosticism
BTC = 'ENRG'
XCP = 'XEP'

BTC_NAME = 'Energycoin'
BTC_CLIENT = 'energycoind'
XCP_NAME = 'Energyparty'
XCP_CLIENT = 'energypartyd'

DEFAULT_RPC_PORT_TESTNET = 15556
DEFAULT_RPC_PORT = 5556

DEFAULT_BACKEND_RPC_PORT_TESTNET = 42705
DEFAULT_BACKEND_RPC_PORT = 22705

UNSPENDABLE_TESTNET = 'mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8'
UNSPENDABLE_MAINNET = 'e26VazRWKbdcEspyFbeKcY3NuQhnUNMBCG'

ADDRESSVERSION_TESTNET = b'\x6f'
PRIVATEKEY_VERSION_TESTNET = b'\xef'
ADDRESSVERSION_MAINNET = b'\x5c'
PRIVATEKEY_VERSION_MAINNET = b'\xdc'
MAGIC_BYTES_TESTNET = b'\xfd\xd6\xb1\xd4'
MAGIC_BYTES_MAINNET = b'\xfc\xd9\xb7\xdd'

BLOCK_FIRST_TESTNET_TESTCOIN = 260
BURN_START_TESTNET_TESTCOIN = BLOCK_FIRST_TESTNET_TESTCOIN
BURN_END_TESTNET_TESTCOIN = BURN_START_TESTNET_TESTCOIN + 10512000

BLOCK_FIRST_TESTNET = BLOCK_FIRST_TESTNET_TESTCOIN
BURN_START_TESTNET =  BURN_START_TESTNET_TESTCOIN
BURN_END_TESTNET = BURN_START_TESTNET + 10512000

BLOCK_FIRST_MAINNET_TESTCOIN = 260
BURN_START_MAINNET_TESTCOIN = BLOCK_FIRST_MAINNET_TESTCOIN
BURN_END_MAINNET_TESTCOIN = BURN_START_MAINNET_TESTCOIN + 10512000

BLOCK_FIRST_MAINNET = 2441800
BURN_START_MAINNET = 2441820
BURN_END_MAINNET = BURN_START_MAINNET + 300

MAX_BURN_BY_ADDRESS = 1000000 * UNIT
BURN_MULTIPLIER = 200

DEFAULT_REGULAR_DUST_SIZE = 1000
DEFAULT_MULTISIG_DUST_SIZE = 2000
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 1000


# UI defaults
DEFAULT_FEE_FRACTION_REQUIRED = .009   # 0.90%
DEFAULT_FEE_FRACTION_PROVIDED = .01    # 1.00%

