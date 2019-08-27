package burp;

import java.util.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.Toolkit;
import javax.swing.JMenuItem;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner
{
    private IExtensionHelpers helpers;
    private static PrintWriter burpStdout;

    private final static String NAME = "Copy requests/responses to clipboard";

    private final static String SKIPPED = "... skipped ...";
    private final static String NEWLINE = "\n";

    private final static int WHOLE_MSG = 0;
    private final static String MENU_WHOLE = "Copy whole message";
    private final static int HEADERS_MSG = 1;
    private final static String MENU_HEADERS = "Copy headers";
    private final static int SELECTED_MSG = 2;
    private final static String MENU_SELECTED = "Copy selected";
    private final static int HIGHLIGHTS_MSG = 3;
    private final static String MENU_HIGHLIGHTS = "Copy issue highlights";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(NAME);
        callbacks.registerContextMenuFactory(this);
        burpStdout = new PrintWriter(callbacks.getStdout(), true);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> l = new ArrayList<>();

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
            || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
            || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
            || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {

            JMenuItem i1 = new JMenuItem(MENU_WHOLE);
            i1.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        copyMessages(invocation, WHOLE_MSG);
                    }
                });
            l.add(i1);

            JMenuItem i2 = new JMenuItem(MENU_HEADERS);
            i2.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        copyMessages(invocation, HEADERS_MSG);
                    }
                });
            l.add(i2);

            JMenuItem i3 = new JMenuItem(MENU_SELECTED);
            i3.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        copyMessages(invocation, SELECTED_MSG);
                    }
                });
            l.add(i3);
        }

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS) {
            JMenuItem i4 = new JMenuItem(MENU_HIGHLIGHTS);
            i4.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        copyMessages(invocation, HIGHLIGHTS_MSG);
                    }
                });
            l.add(i4);
        }

        return l;
    }

    private void copyMessages(IContextMenuInvocation invocation, int option) {
        IHttpRequestResponse httpReqRes = null;

        byte [] httpMessage = null;
        String headers = null;

        List<int[]> markerIndexes = null;
        IHttpRequestResponseWithMarkers reqRespM = null;

        String retString = null;

        // in case issue is selected, use it
        // otherwise, fall back to selected messages
        if (invocation.getSelectedIssues() != null) {
            // take only the first issue and message out of all available
            httpReqRes = invocation.getSelectedIssues()[0].getHttpMessages()[0];
            // in case the message includes markers, store it into specific variable
            if (httpReqRes instanceof IHttpRequestResponseWithMarkers) {
                reqRespM = (IHttpRequestResponseWithMarkers) httpReqRes;
            }
        } else if (invocation.getSelectedMessages() != null) {
            // take only the first message out of all available
            httpReqRes = invocation.getSelectedMessages()[0];
        } else {
            burpStdout.println("nothing to copy");
            return;
        }

        switch (invocation.getInvocationContext()) {
        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST :
        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST :
            httpMessage = httpReqRes.getRequest();
            IRequestInfo reqI = helpers.analyzeRequest(httpReqRes);
            headers = processHeaders(reqI.getHeaders());
            break;
        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE :
        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE :
        case IContextMenuInvocation.CONTEXT_SCANNER_RESULTS : /* get highlighted items only from response */
            httpMessage = httpReqRes.getResponse();
            IResponseInfo respI = helpers.analyzeResponse(httpMessage);
            headers = processHeaders(respI.getHeaders());

            if (reqRespM != null) {
                markerIndexes = reqRespM.getResponseMarkers();
            }
            break;
        default:
            burpStdout.println("unknown invocation context: " + invocation.getInvocationContext());
            return;
        }

        switch (option) {
        case WHOLE_MSG:
            retString = new String(httpMessage).replaceAll("\r", "");
            break;
        case HEADERS_MSG:
            retString = headers;
            retString += NEWLINE;
            retString += SKIPPED;
            break;
        case SELECTED_MSG:
            retString = headers;
            retString += NEWLINE;
            retString += SKIPPED;
            retString += NEWLINE;
            String selected = null;
            int[] selection = invocation.getSelectionBounds();
            if ((selection != null) && (selection[0] != selection[1])) {
                selected = (new String(httpMessage)).substring(selection[0], selection[1]);
            }
            retString += selected;
            retString += NEWLINE;
            retString += SKIPPED;
            break;
        case HIGHLIGHTS_MSG:
            retString = headers;
            retString += NEWLINE;
            retString += SKIPPED;
            retString += NEWLINE;

            List<String> markers = processMarkers(markerIndexes, httpMessage);
            for (String marker : markers) {
                retString += marker;
                retString += NEWLINE;
                retString += SKIPPED;
                retString += NEWLINE;
            }
            break;
        }

        Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(retString), this);
    }

    private static String processHeaders(List<String> headers) {
        String ret = "";
        for (String header : headers) {
            if (header.toLowerCase().startsWith("null"))
                continue;
            ret += header + NEWLINE;
        }
        return ret;
    }

    private static List<String> processMarkers(List<int[]> markerIndexes, byte[] httpMessage) {
        List<String> markers = new ArrayList<>();
        int EXTRA = 50;
        int start;
        int stop;

        for (int[] markerIndex : markerIndexes) {
            start = markerIndex[0] - EXTRA > 0 ? markerIndex[0] - EXTRA : 0;
            stop = markerIndex[1] + EXTRA < httpMessage.length ? markerIndex[1] + EXTRA : httpMessage.length - 1;

            byte[] marker = Arrays.copyOfRange(httpMessage, start, stop);
            markers.add(new String(marker));
        }

        return markers;
    }

    @Override
    public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}
