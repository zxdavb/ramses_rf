"""A CLI for the ramses_rf library.

ramses_rf is used to parse/process Honeywell's RAMSES-II RF protocol as used for
Heating (CH/DHW) and HVAC (ventilation) control.
"""

try:
    from ramses_cli.client import main

except ModuleNotFoundError:
    import os
    import sys

    sys.path.append(f"{os.path.dirname(__file__)}/src")

    from ramses_cli.client import main

if __name__ == "__main__":
    main()
