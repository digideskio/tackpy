# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import sys
from tack.commands.Command import Command
from tack.structures.TackActivation import TackActivation
from tack.structures.TackExtension import TackExtension
from tack.tls.TlsCertificate import TlsCertificate

class PackCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "otba", "vx")
        self.outputFile, self.outputFileName = self.getOutputFile()
        self.tack = self.getTack()
        self.breakSignatures = self.getBreakSignatures()
        self.activationFlag = self._getActivationFlag()

    def execute(self):
        tackExtension = TackExtension.create(self.tack, self.breakSignatures,
                                                self.activationFlag)

        #tlsCertificate = TlsCertificate.create(tackExtension)
        self.outputFile.write(tackExtension.serializeAsPem())
        self.printVerbose(str(tackExtension))
        
    def _getActivationFlag(self):
        activation_flag = self._getOptionValue("-a")

        if activation_flag is None:
            return 0

        try:
            activation_flag = int(activation_flag) # Could raise ValueError
            if activation_flag < 0 or activation_flag > 1:
                raise ValueError()
        except ValueError:
            self.printError("Bad activation_flag: %s" % activation_flag)

        return activation_flag


    @staticmethod
    def printHelp():
        print(
"""Takes the input Tack, Break Sigs, and Activation Flag, and produces a 
TACK_Extension from them.

Optional arguments:
  -v                 : Verbose
  -t TACK            : Include Tack from this file.
  -b BREAKSIGS       : Include Break Signatures from this file.
  -a FLAG            : Activation flag (0 or 1)
  -o FILE            : Write the output to this file (instead of stdout)
""")
