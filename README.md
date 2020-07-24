Copy requests/responses to clipboard plugin for Burp Suite
==========================================================

Copies selected request/response to clipboard with some optional post-processing.

Available functions:
 - Copy request/response as-is
 - Copy only headers
 - Copy only selected part with headers
 - Copy Burp's highlights in case finding is selected

Building
--------

 - Execute `gradle build` in the project's root directory
 - Grab `burp_copy-to-clipboard.jar` from `./build/libs/`

License
-------

The whole project is available under MIT license, see `LICENSE.txt`.

Thanks to https://github.com/OgaworldEX/BurpExtender_OgaCopy and
https://github.com/silentsignal/burp-requests for some snippets. :-)

Thanks to https://github.com/sapo/sscan.git for examples how to use markers.
