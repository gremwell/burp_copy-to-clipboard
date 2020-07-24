# Copy requests/responses to clipboard plugin for Burp Suite

Copies selected request/response to clipboard with some optional post-processing.

## Features

![copying features](/scr_copy-entries.png)

- Copy request/response as-is ("Copy whole message" context menu)
- Copy only headers ("Copy headers" context menu)
- Copy only selected part with headers ("Copy selected" context menu)

![copy issue highlights](/scr_issue-highlights.png)

- Copy Burp's highlights in case finding is selected ("Copy issue highlights"
  context menu if Burp's finding is selected)

![config menu](/scr_config-menu.png)

- Configurable filler string. See Burp's main menu "Copy to Clipboard" entry.
- Minimize too long HTTP headers: make a long header to fit one line by
  inserting filler instead of excessive content. This can be enabled via
  settings menut.
- Configuration is persistent across Burp restarts.

# Building

 - Execute `gradle build` in the project's root directory
 - Grab `burp_copy-to-clipboard.jar` from `./build/libs/`

# License

The whole project is available under MIT license, see `LICENSE.txt`.

Thanks to https://github.com/OgaworldEX/BurpExtender_OgaCopy,
https://github.com/silentsignal/burp-requests and
https://github.com/PortSwigger/backslash-powered-scanner/ for some snippets. :-)

Thanks to https://github.com/sapo/sscan.git for examples how to use markers.
