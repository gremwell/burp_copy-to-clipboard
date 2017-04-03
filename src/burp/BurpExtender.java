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
    private final static String NEWLINE = "\r\n";

    private final static int WHOLE_MSG = 0;
    private final static String MENU_WHOLE = "Copy whole message";
    private final static int HEADERS_MSG = 1;
    private final static String MENU_HEADERS = "Copy headers";
    private final static int SELECTED_MSG = 2;
    private final static String MENU_SELECTED = "Copy selected";

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

        return l;
    }

    private void copyMessages(IContextMenuInvocation invocation, int option) {
        IHttpRequestResponse [] httpReqRes = invocation.getSelectedMessages();
        if(httpReqRes.length < 0){
            return;
        }

        byte [] httpMessage = null;
        String headers = null;
        String selected = null;
        int[] selection = invocation.getSelectionBounds();

        switch (invocation.getInvocationContext()) {
        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST :
        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST :
            httpMessage = httpReqRes[0].getRequest();
            IRequestInfo reqI = helpers.analyzeRequest(httpReqRes[0]);
            headers = processHeaders(reqI.getHeaders());
            break;
        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE :
        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE :
            httpMessage = httpReqRes[0].getResponse();
            IResponseInfo respI = helpers.analyzeResponse(httpMessage);
            headers = processHeaders(respI.getHeaders());
            break;
        }

        if ((selection != null) && (selection[0] != selection[1])) {
            selected = (new String(httpMessage)).substring(selection[0], selection[1]);
        }

        String retString = null;

        switch (option) {
        case WHOLE_MSG:
            retString = new String(httpMessage);
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
            retString += selected;
            retString += NEWLINE;
            retString += SKIPPED;
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

    @Override
    public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}
