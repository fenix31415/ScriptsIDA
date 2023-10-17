# IDA Scripts

Several scripts for IDA. There are two types:

* Helpers. Provides functions/hotkeys for RE.
* Auto RE. Run this once, it set some variables, structures and functions in your db.

To use Helpers, run `mt.py` as a regular script. You can use functions from Helpers scripts this way: `HelperName.func(..)`. Use `help()` function for usage, also there is a description at the start of every Helper script.

To use Auto RE, just run it, then call `run_all()` function.

Helper scripts:

* REL_ID_Offset -- Helps with finding REL::ID and offset of function spot and vice versa
* CreateVFTable -- Helps with creating/updating structs for vftables

Auto RE scripts:

* GameSettings -- Populates your db with structs for settings, global variables, ctors and dtors
* FixedStrings -- populates your db with fixed string global variables, ctors and dtors
