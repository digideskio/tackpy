# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import getopt
import getpass
import sys
import time
from tack.structures.TackKeyFile import TackKeyFile
from tack.structures.TackExtension import TackExtension
from tack.structures.Tack import Tack
from tack.tls.TlsCertificate import TlsCertificate
from tack.util.Time import Time
from tack.crypto.openssl.OpenSSL import openssl as o
from tack.compat import bytesToStr, readStdinBinary
from tack.version import __version__
from tack.InvalidPasswordException import InvalidPasswordException

class Command:

    def __init__(self, argv, options, flags, allowArgRemainder=0):
        try:
            self.flags                  = flags
            self.options                = ":".join(options) + ":"
            self.values, self.argRemainder = getopt.gnu_getopt(argv, self.options + self.flags)
            if not allowArgRemainder and self.argRemainder:
                self.printError("Too many arguments: %s" % self.argRemainder)
            if allowArgRemainder != len(self.argRemainder):
                self.printError("Wrong number of arguments: %d should be %d" % \
                    (len(self.argRemainder), allowArgRemainder))

            # Handle flags
            if self._containsOption("-x"):
                o.setInitError("requested from command line")
                o.enabled = False
            if self._containsOption("-v"):
                self.verbose = True
            else:
                self.verbose = False

        except getopt.GetoptError as e:
            self.printError(e)

    @staticmethod
    def getCryptoVersion():
        if o.enabled:
            cryptoVersion = "%s" % bytesToStr(o.SSLeay_version(0))
        else:
            cryptoVersion = "python crypto - %s" % o.initErrorString
        return cryptoVersion

    def writeCryptoVersion(self):
        sys.stderr.write("Crypto          = %s\n" % Command.getCryptoVersion())       

    def getPassword(self):
        return self._getOptionValue("-p")

    def getKeyFile(self, password):
        keyPemFile = self.argRemainder[0]
        if not password:
            password = self._promptPassword()

        try:
            if keyPemFile == "-":
                keyPemData = sys.stdin.read()
            else:
                keyPemData = open(keyPemFile, "rU").read()

            while True:
                try:
                    inKey = TackKeyFile.createFromPem(keyPemData, password)
                    return inKey
                except InvalidPasswordException as ipe:
                    sys.stderr.write("Password incorrect!\n")
                    password = self._promptPassword()
                except SyntaxError as e:
                    self.printError("Error processing TACK Key File: %s\n%s" % (keyPemFile, e))

        except IOError as e:
            self.printError("Error opening TACK Key File: %s\n%s" % (keyPemFile, e))

    def getTacks(self):
        fileName = self.argRemainder[0]
        try:
            contents = open(fileName, "r").read()
            return Tack.createFromPemList(contents)
        except IOError as e:
            self.printError("Error opening tacks: %s\n%s" % (fileName, e))
        except SyntaxError as e:
            self.printError("Error parsing tacks: %s\n%s" % (fileName, e))

    def getTackExtension(self, extenderFormat=False):
        fileName = self.argRemainder[0]
        try:
            contents = open(fileName, "r").read()
            return TackExtension.createFromPem(contents, extenderFormat)
        except IOError as e:
            self.printError("Error opening extension: %s\n%s" % (fileName, e))
        except SyntaxError as e:
            self.printError("Error parsing extension: %s\n%s" % (fileName, e))

    def getCertificate(self):
        certificateFile = self.argRemainder[1]
        try:
            if certificateFile == "-":
                # Read as binary
                certificateBytes = readStdinBinary()
            else:
                certificateBytes = bytearray(open(certificateFile, "rb").read())
                
            return TlsCertificate.createFromBytes(certificateBytes)
        except SyntaxError as e:
            self.printError("Certificate malformed: %s\n%s" % (certificateFile, e))
        except IOError as e:
            self.printError("Error opening certificate: %s\n%s" % (certificateFile, e))

    def getOutputFile(self):
        output = None

        try:
            output = self._getOptionValue("-o")

            if output is None:
                return sys.stdout, None
            else:
                return open(output, "w"), output
        except IOError:
            self.printError("Error opening output file: %s" % output)

    def getOutputFileName(self):
        return self._getOptionValue("-o")

    def addPemComments(self, inStr):
        """Add pre-PEM metadata/comments to PEM strings."""
        versionStr = __version__
        timeStr = Time.posixTimeToStr(time.time(), True)
        outStr = "Created by tack.py %s\nCreated at %s\n%s" %\
                 (versionStr, timeStr, inStr)
        return outStr

    def _promptPassword(self):
        return getpass.getpass("Enter password for key file: ")

    def _getOptionValue(self, flag):
        for option, value in self.values:
            if option == flag:
                return value

        return None

    def _containsOption(self, flag):
        for option, value in self.values:
            if option == flag:
                return True

    def _readFileTextAndBinary(self, fname):
        try:
            # Read both binary (bytearray) and text (str) versions of the input
            try:
                if fname == "-":
                    # Read as binary
                    binary = readStdinBinary()
                else:      
                    binary = bytearray(open(fname, "rb").read())
                text = bytesToStr(binary, "ascii")
            except UnicodeDecodeError:
                # So it must be a binary file, not text
                text = None

            return text, binary
        except IOError:
            self.printError("Error opening file: %s" % fname)

    def printError(self, error):
        """Print error message and exit"""
        sys.stderr.write("ERROR: %s\n" % error)
        sys.exit(-1)

    def printVerbose(self, s):
        if self.verbose:
            self.writeCryptoVersion()
            sys.stderr.write(s)     
