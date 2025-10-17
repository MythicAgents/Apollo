"""
Utility functions and constants for Apollo translator.
Since Apollo uses mythic_encrypts=True, this translator is primarily pass-through
but required for httpx profile compatibility.
"""

# Apollo uses JSON serialization directly, so no special message constants needed
# The translator will pass through JSON messages without modification
