# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
from tack.compat import a2b_hex
from tack.crypto.ECGenerator import ECGenerator
from tack.structures.Tack import Tack
from tack.structures.TackKeyFile import TackKeyFile
from tack.util.Time import Time

class StructuresTest(unittest.TestCase):

    def test_Tack(self):
        s = """
-----BEGIN TACK-----
TAmsAZIpzR+MYwQrsujLhesvpu3dRc5ROhfgySqUVkU1p1hdXo+PwQrmaQo9B9+o
hecRrWElh3yThwgYQRgbSwAAAY0cQDHeDLGfKtuw0c17GzHvjuPrWbdEWa75S0gL
7u64XGTJQUtzAwXIWOkQEQ0BRUlbzcGEa9a1PBhjmmWFNF+kGAswhLnXc5qL4y/Z
PDUV0rzIIYjXP58T5pphGKRgLlK3Aw==
-----END TACK-----"""

        t = Tack().createFromPem(s)

        assert(t.public_key.getRawKey() == a2b_hex("4c09ac019229cd1f8c63042bb2e8"
                                       "cb85eb2fa6eddd45ce513a17e0c9"
                                       "2a94564535a7585d5e8f8fc10ae6"
                                       "690a3d07dfa885e711ad6125877c"
                                       "9387081841181b4b"))
        assert(Time.posixTimeToStr(t.expiration*60) == "2019-06-25T22:24Z")
        assert(t.generation == 0)
        assert(t.target_hash == a2b_hex("31de0cb19f2adbb0d1cd7b1b31ef8ee3eb59b74459aef94b480beeeeb85c64c9"))
        assert(t.signature == a2b_hex("414b730305c858e910110d0145495"
                                      "bcdc1846bd6b53c18639a6585345f"
                                      "a4180b3084b9d7739a8be32fd93c3"
                                      "515d2bcc82188d73f9f13e69a6118"
                                      "a4602e52b703"))

    def test_KeyFile(self):
        s = """
    -----BEGIN TACK PRIVATE KEY-----
    AQAAIAAjOxiOdpiMo5qWidXwBTqJHxW5X1zRDBOA4ldqqFuKOSh6JJdrbXk1WsMN
    X/gyaVuHMBhC/g/rjtu/EnmIHoUuT9348iXeeROaLVRPdNqwr+5KEfjtTY7uXA6Q
    mhRUn+XmDePKRucRHYkcQaFPnzglrQ120Dh6aXD4PbtJMWajJtzTMvtEo9pNZhoM
    QTNZNoM=
    -----END TACK PRIVATE KEY-----"""
        publicKey = a2b_hex("87301842fe0feb8edbbf1279881e852e"
                            "4fddf8f225de79139a2d544f74dab0af"
                            "ee4a11f8ed4d8eee5c0e909a14549fe5"
                            "e60de3ca46e7111d891c41a14f9f3825")
        privateKey = a2b_hex("fc815de8b1de13a436e9cd69742cbf2c"
                             "d4c1c9bb33e023401d9291cf2781b754")
        kf = TackKeyFile.createFromPem(s, "asdf")
        assert(kf.getPublicKey().getRawKey() == publicKey)
        assert(kf.getPrivateKey().getRawKey() == privateKey)
        kf2 = TackKeyFile.createFromPem(kf.serializeAsPem(), "asdf")
        assert(kf2.getPublicKey().getRawKey() == publicKey)
        assert(kf2.getPrivateKey().getRawKey() == privateKey)
        public_key, private_key = ECGenerator.generateECKeyPair()
        kf3  = TackKeyFile.create(public_key, private_key, "123")
        kf4 = TackKeyFile.createFromPem(kf3.serializeAsPem(), "123")
        assert(kf3.getPublicKey().getRawKey() == kf4.getPublicKey().getRawKey())

if __name__ == '__main__':
    unittest.main()
