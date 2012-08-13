# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

class TackActivation:
    NONE = 0
    FIRST_ACTIVE  = 1
    SECOND_ACTIVE = 2
    BOTH_ACTIVE = 3
    ALL      = (NONE, FIRST_ACTIVE, SECOND_ACTIVE, BOTH_ACTIVE)
    STRINGS  = ["none", "first_active", "second_active", "both_active"]