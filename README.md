# Firewall_Enumerator_BOF

## What is this?
This is meant as a supplement to interact with the Windows firewall via COM interfaces.

## Did you derive inspiration from anywhere?
Yes, of course.  [@TheRealWover](https://twitter.com/TheRealWover)'s existing code from `Donut` a bit of insight in how to implement `uuid`'s functionality without losing sleep.  Thank you!

## Why?
COM in general through lower-level languages is a pain.  This was meant to show that we can intermix convenience interfaces with C++ in `BOF` files.

## What else does this show?
This shows that it's possible to use C++ classes/wrappers within `BOF` files, eliminating the need to `BEGIN_INTERFACE` and lose ourselves to reimplementation depths of despair in straight `C`.

## What are the options this currently supports
- Fetching the total number of known Windows firewall rules via: `fw_walk total`
- Enumerating each of the three default locations for firewalls configurations (profile, domain, and public) via: `fw_walk status`
- The ability to disable (assuming you have sufficient privileges) all three default firewalls (profile, domian, and public) via: `fw_walk enable`
- The ability to enable/revert your actions (assuming you have sufficient privileges) all three default firewalls (profile, domain, and public) via: `fw_walk enable`

## How do I run this?
1. In this case, you have two options:
	1. Use the existing, compiled object file, located in the `dist` directory (AKA proceed to major step two)
    2. Compile from source via the `Makefile`
        1. `cd src`
        2. `make clean`
        3. `make`
2. Load the `Aggressor` file, in the `Script Manager`, located in the `dist` directory
3. Within a provided `Beacon`, `beacon> fw_walk` to display the previously-mentioned options

## Any known downsides?
- We're still using the `Win32` API and `Dynamic Function Resolution`.  This is for you to determine as far as "risk"
- You may attempt to incur a privileged action without sufficient requisite permissions.  I can't keep you from burning your hand.

## Where can we go from here?
The sky's the limit:
- Add a rule for your own application
- Add a rule for an interface of your choosing
- Delete rules at will