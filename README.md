# Copy requests/responses to clipboard plugin for Burp Suite

Copies selected request/response to clipboard with some optional post-processing.

The idea behind this plugin was to speedup the process of documenting HTTP
request/response exchanges between a web application and a corresponding web
server.

What a pentester has often has to do is to provide evidences on how a web
application behaves. It implies a lot of copy-pasting from Burp to some document
processing software. It is not a big problem if the researcher just needs to
copy the whole request/response, however, quite often one needs only a
particular part of the response, for instance, with `alert(1)` payload. The
pentester (and the report reader) may not need the whole response. In that case
copy-pasting becomes a problem as a lot of manual post-processing has to be made
like removing unnecessary content and adding some words which mark such removed
data.

This plugin allows the pentester to select (highlight with mouse cursor) the
important content (like `alert(1)`), access context menu and select "Copy
selected" entry. After that system's clipboard will have only HTTP headers, the
selected data and fillers around it. Then the pentester can just paste the
content to where it should be.

## Author's approach

The author of this plugin uses LibreOffice to write reports. He created two
VisualBasic macros which significantly speedup pasting and formatting HTTP
request/response pairs.

The macros below pastes from the system's clipboard the current content and
applies a formatting style named "Request" (see the last few lines of the
function). It also leaves the empty line with after the data marked with style
"Text Body".

``` basic
Sub InsertRequest
  Dim oClip, oClipContents, oTypes
  Dim oConverter, convertedString$
  Dim i%, iPlainLoc%

  iPlainLoc = -1

  Dim s$ : s$ = "com.sun.star.datatransfer.clipboard.SystemClipboard"
  oClip = createUnoService(s$)
  oConverter = createUnoService("com.sun.star.script.Converter")

  'Print "Clipboard name = " & oClip.getName()
  'Print "Implemantation name = " & oClip.getImplementationName()
  oClipContents = oClip.getContents()
  oTypes = oClipContents.getTransferDataFlavors()

  Dim msg$, iLoc%, outS
  msg = ""
  iLoc = -1
  For i=LBound(oTypes) To UBound(oTypes)
    If oTypes(i).MimeType = "text/plain;charset=utf-16" Then
      iPlainLoc = i
      Exit For
    End If
  Next
  If (iPlainLoc >= 0) Then
    convertedString = oConverter.convertToSimpleType( _
         oClipContents.getTransferData(oTypes(iPlainLoc)), _
         com.sun.star.uno.TypeClass.STRING)
    convertedString = Replace(convertedString, Chr(13), "")
    'MsgBox convertedString
  End If

  REM pasting cleared clipboard
  Dim oDoc As Object
  Dim oText As Object
  Dim oVCurs As Object
  Dim oTCurs As Object

  oDoc = ThisComponent
  oText = oDoc.Text
  oVCurs = oDoc.CurrentController.getViewCursor()
  oTCurs = oText.createTextCursorByRange(oVCurs.getStart())
  oText.insertString(oTCurs, convertedString, FALSE)

  REM Applying style to the inserted text
  oTCurs.ParaStyleName = "Request"

  REM fixing the end of new paragraph and setting style back to default
  oText.insertControlCharacter(oTCurs, com.sun.star.text.ControlCharacter.PARAGRAPH_BREAK, false)
  oTCurs.ParaStyleName = "Text Body"
End Sub
```

The following function is the same, it just sets the style named "Response" to
the pasted data.

``` basic
Sub InsertResponse
  Dim oClip, oClipContents, oTypes
  Dim oConverter, convertedString$
  Dim i%, iPlainLoc%

  iPlainLoc = -1

  Dim s$ : s$ = "com.sun.star.datatransfer.clipboard.SystemClipboard"
  oClip = createUnoService(s$)
  oConverter = createUnoService("com.sun.star.script.Converter")

  'Print "Clipboard name = " & oClip.getName()
  'Print "Implemantation name = " & oClip.getImplementationName()
  oClipContents = oClip.getContents()
  oTypes = oClipContents.getTransferDataFlavors()

  Dim msg$, iLoc%, outS
  msg = ""
  iLoc = -1
  For i=LBound(oTypes) To UBound(oTypes)
    If oTypes(i).MimeType = "text/plain;charset=utf-16" Then
      iPlainLoc = i
      Exit For
    End If
  Next
  If (iPlainLoc >= 0) Then
    convertedString = oConverter.convertToSimpleType( _
         oClipContents.getTransferData(oTypes(iPlainLoc)), _
         com.sun.star.uno.TypeClass.STRING)
    convertedString = Replace(convertedString, Chr(13), "")
    'MsgBox convertedString
  End If

  REM pasting cleared clipboard
  Dim oDoc As Object
  Dim oText As Object
  Dim oVCurs As Object
  Dim oTCurs As Object

  oDoc = ThisComponent
  oText = oDoc.Text
  oVCurs = oDoc.CurrentController.getViewCursor()
  oTCurs = oText.createTextCursorByRange(oVCurs.getStart())
  oText.insertString(oTCurs, convertedString, FALSE)

  REM Applying style to the inserted text
  oTCurs.ParaStyleName = "Response"

  REM fixing the end of new paragraph and setting style back to default
  oText.insertControlCharacter(oTCurs, com.sun.star.text.ControlCharacter.PARAGRAPH_BREAK, false)
  oTCurs.ParaStyleName = "Text Body"
End Sub
```

LibreOffice software has functionality to assign keyboard shortcuts to specific
macros: Tools --> Customize --> Keyboard, select "Category" "LibreOffice
macros" and find yours.

Once configured it makes copy-pasting process really quick: select the desired
data in Burp (left mouse click and highlight), select the corresponding item in
context menu (right mouse click, find entry, left mouse click), switch to
Writer, press `Ctrl+Shift+Q` for query (in author's case) or `Ctrl+Shift+R` for
response.

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
