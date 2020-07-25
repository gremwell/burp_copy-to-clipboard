package burp;

import java.util.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.Toolkit;
import java.awt.GridLayout;
import java.awt.Frame;
import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.text.NumberFormatter;
import java.text.NumberFormat;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner
{
    private IExtensionHelpers helpers;
    private static PrintWriter burpStdout;
    private IBurpExtenderCallbacks callbacks;

    private final static String NAME = "Copy requests/responses to clipboard";

    private final static String NEWLINE = "\n";

    private final static int WHOLE_MSG = 0;
    private final static String MENU_WHOLE = "Copy whole message";
    private final static int HEADERS_MSG = 1;
    private final static String MENU_HEADERS = "Copy headers";
    private final static int SELECTED_MSG = 2;
    private final static String MENU_SELECTED = "Copy selected";
    private final static int HIGHLIGHTS_MSG = 3;
    private final static String MENU_HIGHLIGHTS = "Copy issue highlights";

    private final static int HEADER_TRAILER_LEN = 10;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks incallbacks)
    {
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(NAME);
        callbacks.registerContextMenuFactory(this);
        burpStdout = new PrintWriter(callbacks.getStdout(), true);
        SwingUtilities.invokeLater(new ConfigMenu(callbacks));
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
        String body = null;

        List<int[]> markerIndexes = null;
        IHttpRequestResponseWithMarkers reqRespM = null;

        String retString = null;

        String skippedString = callbacks.loadExtensionSetting("skipped");
        boolean doMinimize = false;
        if ((callbacks.loadExtensionSetting("minimize") != null) && (callbacks.loadExtensionSetting("minimize").equals("true"))) {
            doMinimize = true;
        }
        int maxHeaderLen = 88;
        if (callbacks.loadExtensionSetting("maxheaderlen") != null) {
            maxHeaderLen = Integer.parseInt(callbacks.loadExtensionSetting("maxheaderlen"));
        }

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
            headers = processHeaders(reqI.getHeaders(), doMinimize, skippedString, maxHeaderLen);
            body = (new String(httpMessage)).substring(reqI.getBodyOffset());
            break;
        case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE :
        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE :
        case IContextMenuInvocation.CONTEXT_SCANNER_RESULTS : /* get highlighted items only from response */
            httpMessage = httpReqRes.getResponse();
            IResponseInfo respI = helpers.analyzeResponse(httpMessage);
            headers = processHeaders(respI.getHeaders(), doMinimize, skippedString, maxHeaderLen);
            body = (new String(httpMessage)).substring(respI.getBodyOffset());

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
            retString = headers;
            retString += NEWLINE;
            retString += body;
            break;
        case HEADERS_MSG:
            retString = headers;
            retString += NEWLINE;
            retString += skippedString;
            break;
        case SELECTED_MSG:
            retString = headers;
            retString += NEWLINE;
            retString += skippedString;
            retString += NEWLINE;
            String selected = null;
            int[] selection = invocation.getSelectionBounds();
            if ((selection != null) && (selection[0] != selection[1])) {
                selected = (new String(httpMessage)).substring(selection[0], selection[1]);
            }
            retString += selected;
            retString += NEWLINE;
            retString += skippedString;
            break;
        case HIGHLIGHTS_MSG:
            retString = headers;
            retString += NEWLINE;
            retString += skippedString;
            retString += NEWLINE;

            List<String> markers = processMarkers(markerIndexes, httpMessage);
            for (String marker : markers) {
                retString += marker;
                retString += NEWLINE;
                retString += skippedString;
                retString += NEWLINE;
            }
            break;
        }

        Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(retString), this);
    }

    private static String processHeaders(List<String> headers, boolean doMinimize, String skippedString, int maxHeaderLen) {
        String ret = "";
        boolean firstLine = true;
        for (String header : headers) {
            if (header.toLowerCase().startsWith("null"))
                continue;
            if (!firstLine && doMinimize && (header.length() > maxHeaderLen)) {
                int l = skippedString.length();
                String h1 = header.substring(0, maxHeaderLen - HEADER_TRAILER_LEN - l - 1);
                String h2 = header.substring(header.length() - HEADER_TRAILER_LEN - 1);
                header = h1 + skippedString + h2;
            }
            ret += header + NEWLINE;
            if (firstLine) {
                firstLine = false;
            }
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

class ConfigMenu implements Runnable, MenuListener, IExtensionStateListener {
    private JMenu menuButton;
    static IBurpExtenderCallbacks callbacks;

    ConfigMenu(final IBurpExtenderCallbacks incallbacks) {
        callbacks = incallbacks;
        callbacks.registerExtensionStateListener(this);
    }

    public void run() {
        menuButton = new JMenu("Copy to Clipboard");
        menuButton.addMenuListener(this);
        JMenuBar burpMenuBar = getBurpFrame().getJMenuBar();
        burpMenuBar.add(menuButton);
    }

    static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    public void menuSelected(MenuEvent e) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                showSettings();
            }
        });
    }

    public void showSettings() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 2));

        HashMap<String, Object> configured = new HashMap<>();

        panel.add(new JLabel("\n" + "skipped string" + ": "));
        String val1 = callbacks.loadExtensionSetting("skipped");
        if (val1 == null) {
            val1 = "...skipped...";
        }
        JTextField box1 = new JTextField(val1);
        panel.add(box1);
        configured.put("skipped", box1);

        panel.add(new JLabel("\n" + "minimize headers" + ": "));
        String val2 = callbacks.loadExtensionSetting("minimize");
        boolean val2x = false;
        if (val2 != null) {
            if (val2.equals("true")) {
                val2x = true;
            }
        }
        JCheckBox box2 = new JCheckBox();
        box2.setSelected(val2x);
        panel.add(box2);
        configured.put("minimize", box2);

        NumberFormat format = NumberFormat.getInstance();
        NumberFormatter onlyInt = new NumberFormatter(format);
        onlyInt.setValueClass(Integer.class);
        onlyInt.setMinimum(1);
        onlyInt.setMaximum(256);
        onlyInt.setAllowsInvalid(false);

        panel.add(new JLabel("\n" + "max header length" + ": "));
        JTextField box3 = new JFormattedTextField(onlyInt);
        String val3 = callbacks.loadExtensionSetting("maxheaderlen");
        int val3x = 88;
        if (val3 != null) {
            val3x = Integer.parseInt(val3);
        }
        box3.setText(String.valueOf(val3x));
        panel.add(box3);
        configured.put("maxheaderlen", box3);

        int result = JOptionPane.showConfirmDialog(getBurpFrame(), panel, "Copy to Clipboard Config", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            for(String key: configured.keySet()) {
                Object val = configured.get(key);
                if (val instanceof JCheckBox) {
                    val = ((JCheckBox) val).isSelected();
                }
                else if (val instanceof JFormattedTextField) {
                    val = Integer.parseInt(((JTextField) val).getText());
                }
                else {
                    val = ((JTextField) val).getText();
                }
                callbacks.saveExtensionSetting(key, encode(val));
            }
        }
    }

    private String encode(Object value) {
        String encoded;
        if (value instanceof Boolean) {
            encoded = String.valueOf(value);
        } else if (value instanceof Integer) {
            encoded = String.valueOf(value);
        } else {
            encoded = (String)value;
        }
        return encoded;
    }

    public void menuDeselected(MenuEvent e) {
    }

    public void menuCanceled(MenuEvent e) {
    }

    public void extensionUnloaded() {
        JMenuBar jMenuBar = getBurpFrame().getJMenuBar();
        jMenuBar.remove(menuButton);
        jMenuBar.repaint();
    }
}
