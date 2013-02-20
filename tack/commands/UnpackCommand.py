# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import sys
from tack.commands.Command import Command
from tack.structures.TackExtension import TackExtension
from tack.tls.TlsCertificate import TlsCertificate

class UnpackCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "o", "vx", 1)
        self.outputFile, self.outputFileName = self.getOutputFile()
        self.tackExtension = self.getTackExtension(extenderFormat=True)

    def execute(self):
        for tack in self.tackExtension.tacks:
            self.outputFile.write(tack.serializeAsPem())
        self.printVerbose(str(self.tackExtension))

    @staticmethod
    def printHelp():
        print(
"""Takes the input TACK Extension, and writes out its tacks.

  unpack EXTENSION
  
  EXTENSION          : Use this Extension file (PEM format, "-" for stdin)

Optional arguments:
  -v                 : Verbose
  -o FILE            : Write the output to this file (instead of stdout)
""")
