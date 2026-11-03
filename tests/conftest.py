import sys

# The converter's runtime surface must hold no bytecode: the safety gate treats
# a __pycache__ there as a finding, because Python would load it in place of
# the audited source. Keep the test run from seeding the checkout with one.
sys.dont_write_bytecode = True
