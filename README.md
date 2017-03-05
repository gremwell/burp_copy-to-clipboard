Copy requests/responses to clipboard plugin for Burp Suite
==========================================================

Copies selected request/response to clipboard with some optional post-processing.

Available functions:
 - Copy request/response as-is
 - Copy only headers

Building
--------

 - Save Burp Extender API into `src` (go to Extender --> APIs, press "Save
   Interface Files" button)
 - Execute `ant`, and you'll have the plugin ready in `burp_copy-to-clipboard.jar`

Dependencies
------------

 - JDK 1.7+
 - Apache ANT (Debian/Ubuntu package: `ant`)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`.

Thanks to https://github.com/OgaworldEX/BurpExtender_OgaCopy and
https://github.com/silentsignal/burp-requests for some snippets. :-)
