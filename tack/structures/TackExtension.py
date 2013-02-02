# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from tack.structures.Tack import Tack
from tack.tls.TlsStructure import TlsStructure
from tack.tls.TlsStructureWriter import TlsStructureWriter
from tack.util.PEMDecoder import PEMDecoder
from tack.util.PEMEncoder import PEMEncoder

class TackExtension(TlsStructure):

    def __init__(self, data=None, extenderFormat=False):
        if data is None:
            return

        TlsStructure.__init__(self, data)
        if extenderFormat:
            extensionType = self.getInt(2)
            if extensionType != 62208:
                raise SyntaxError("Bad TLS Extension type")
            extensionLen = self.getInt(2)
            
        self.tacks            = self._parseTacks()
        self.activation_flags = self.getInt(1)

        if self.activation_flags > 3:
            raise SyntaxError("Bad activation_flag value")

        if self.index != len(data):
            raise SyntaxError("Excess bytes in TACK_Extension")
        if extenderFormat and self.index != 4 + extensionLen:
            raise SyntaxError("Bad TLS Extension length: %d %d")

    @classmethod
    def createFromPem(cls, data, extenderFormat=False):
        return cls(PEMDecoder(data).decode("TACK EXTENSION"), extenderFormat)

    @classmethod
    def create(cls, tacks, activation_flags):
        tackExtension                = cls()
        tackExtension.tacks          = tacks
        tackExtension.activation_flags = activation_flags

        return tackExtension

    def serialize(self, extenderFormat=False):
        assert(self.tacks)
        w = TlsStructureWriter(self._getSerializedLength(extenderFormat))
        if extenderFormat:
            w.add(62208, 2)
            w.add(len(self.tacks) * Tack.LENGTH + 3, 2)
        w.add(len(self.tacks) * Tack.LENGTH, 2)
        for tack in self.tacks:
            w.add(tack.serialize(), Tack.LENGTH)
        w.add(self.activation_flags, 1)
        return w.getBytes()

    def serializeAsPem(self, extenderFormat=False):
        return PEMEncoder(self.serialize(extenderFormat)).encode("TACK EXTENSION")

    def verifySignatures(self):
        for tack in self.tacks:
            if not tack.verifySignature():
                return False
        return True

    def _getSerializedLength(self, extenderFormat=False):
        assert(self.tacks)
        length = len(self.tacks) * Tack.LENGTH
        if extenderFormat:
            length += 4
        return length + 3 # 2 byes length field, 1 byte flags

    def _parseTacks(self):
        tacksLen = self.getInt(2)
        if tacksLen > 2 * Tack.LENGTH or tacksLen < Tack.LENGTH or tacksLen == 0:
            raise SyntaxError("tacks wrong number: %d" % tacksLen)
        elif tacksLen % Tack.LENGTH != 0:
            raise SyntaxError("tacks wrong size: %d" % tacksLen)

        tacks = []
        b2 = self.getBytes(tacksLen)
        while b2:
            tacks.append(Tack(b2[:Tack.LENGTH]))
            b2 = b2[Tack.LENGTH:]
        
        return tacks

    def __str__(self):
        result = ""
        assert(self.tacks)
        for tack in self.tacks:
            result += str(tack)

        result += "activation_flags = %d\n" % self.activation_flags

        return result
