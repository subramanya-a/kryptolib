#!/usr/bin/env python
# encoding: utf-8

import sys
import binascii
sys.path.append("..")

from kryptolib import krypto_obj 
from eddsa_test_sample import *

EdDSA_Test_Samples = EdDSA_TEST_SAMPLES['Ed25519']
krypto = krypto_obj('Ed25519')


for indx, ts in enumerate(EdDSA_Test_Samples):
    # print(ts['SECRET_KEY'])
    # print(ts['PUBLIC_KEY'])
    # print(ts['MESSAGE'])
    # print(ts['SIGNATURE'])

    secret = binascii.unhexlify(ts['SECRET_KEY'])
    public = binascii.unhexlify(ts['PUBLIC_KEY'])
    msg = binascii.unhexlify(ts['MESSAGE'])
    signature = binascii.unhexlify(ts['SIGNATURE'])

    privkey,pubkey = krypto.keygen(secret)
    try:
        assert public == pubkey
        assert signature == krypto.sign(privkey, pubkey, msg)
        assert krypto.verify(public, msg, signature)
    except Exception as e:
        print('Test{} Failed:{}'.format((indx+1),e))
    else:
        print("Test{} Passed".format((indx+1)))
    finally:
        pass