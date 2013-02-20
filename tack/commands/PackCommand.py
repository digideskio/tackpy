# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import sys
from tack.commands.Command import Command
from tack.structures.TackExtension import TackExtension
from tack.tls.TlsCertificate import TlsCertificate

class PackCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "oa", "vx", 1)
        self.outputFile, self.outputFileName = self.getOutputFile()
        self.tacks = self.getTacks()
        self.activationFlags = self._getActivationFlags()

    def execute(self):
        tackExtension = TackExtension.create(self.tacks, self.activationFlags)

        self.outputFile.write(self.addPemComments(tackExtension.serializeAsPem(True)))
        self.printVerbose(str(tackExtension))
        
    def _getActivationFlags(self):
        activation_flags = self._getOptionValue("-a")

        if activation_flags is None:
            return 0

        try:
            activation_flags = int(activation_flags) # Could raise ValueError
            if activation_flags < 0 or activation_flags > 3:
                raise ValueError()
        except ValueError:
            self.printError("Bad activation_flags: %s" % activation_flags)

        return activation_flags


    @staticmethod
    def printHelp():
        print(
"""Takes a file containing 1 or more TACK PEM files, and write out a TACK
Extension containing them.

  pack TACKS
  
  TACKS              : Use this Tacks file (PEM format, "-" for stdin)


Optional arguments:
  -v                 : Verbose
  -a FLAG            : Activation flag (0...3)
  -o FILE            : Write the output to this file (instead of stdout)
""")
