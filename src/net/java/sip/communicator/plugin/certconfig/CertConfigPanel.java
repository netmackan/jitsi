/*
 * Jitsi, the OpenSource Java VoIP and Instant Messaging client.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.sip.communicator.plugin.certconfig;

import java.awt.*;
import java.awt.event.*;
import java.security.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;
import javax.net.ssl.SSLContext;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

import net.java.sip.communicator.plugin.desktoputil.*;
import net.java.sip.communicator.service.certificate.*;
import net.java.sip.communicator.service.gui.*;

import org.jitsi.service.resources.*;
import org.jitsi.util.*;

/**
 * Advanced configuration form to define client TLS certificate templates.
 *
 * @author Ingo Bauersachs
 */
public class CertConfigPanel
    extends TransparentPanel
    implements ConfigurationForm, ActionListener, ListSelectionListener
{
    /**
     * Logger of this class.
     */
    private static final Logger logger 
            = Logger.getLogger(CertConfigPanel.class);
    
    // ------------------------------------------------------------------------
    // Fields
    // ------------------------------------------------------------------------
    private static final long serialVersionUID = 2324122652952574574L;
    private ResourceManagementService R;
    private CertConfigTableModel model;

    // ------------------------------------------------------------------------
    // GUI members
    // ------------------------------------------------------------------------
    private JButton cmdAdd;
    private JButton cmdRemove;
    private JButton cmdEdit;
    private JTable tblCertList;
    private JRadioButton rdoUseWindows;
    private JRadioButton rdoUseJava;
    private SIPCommCheckBox chkEnableRevocationCheck;
    private SIPCommCheckBox chkEnableOcsp;
    private CipherSuitesPanel cipherPanel;

    // ------------------------------------------------------------------------
    // initialization
    // ------------------------------------------------------------------------
    /**
     * Creates a new instance of this class.
     */
    public CertConfigPanel()
    {
        R = CertConfigActivator.R;
        model = new CertConfigTableModel();
        initComponents();
        valueChanged(null);
    }

    private void initComponents()
    {
        this.setLayout(new BorderLayout());
        
        TransparentPanel oldPanel = new TransparentPanel();
        BoxLayout boxLayout = new BoxLayout(oldPanel, BoxLayout.Y_AXIS);
        oldPanel.setLayout(boxLayout);
        SIPCommTabbedPane tabbedPane = new SIPCommTabbedPane();
        tabbedPane.add("Validation", oldPanel);
        
        // trusted root CA source selection
        if (OSUtils.IS_WINDOWS)
        {
            JPanel pnlCertConfig = new TransparentPanel(new GridLayout(2, 1));
            pnlCertConfig.setBorder(BorderFactory.createTitledBorder(
                R.getI18NString("plugin.certconfig.TRUSTSTORE_CONFIG")));
            oldPanel.add(pnlCertConfig);

            ButtonGroup grpTrustStore = new ButtonGroup();

            rdoUseJava = new SIPCommRadioButton();
            rdoUseJava.setText(
                R.getI18NString("plugin.certconfig.JAVA_TRUSTSTORE"));
            rdoUseJava.addActionListener(this);
            grpTrustStore.add(rdoUseJava);
            pnlCertConfig.add(rdoUseJava);

            rdoUseWindows = new SIPCommRadioButton();
            rdoUseWindows.setText(
                R.getI18NString("plugin.certconfig.WINDOWS_TRUSTSTORE"));
            rdoUseWindows.addActionListener(this);
            grpTrustStore.add(rdoUseWindows);
            pnlCertConfig.add(rdoUseWindows);

            if ("Windows-ROOT".equals(CertConfigActivator.getConfigService()
                .getProperty(CertificateService.PNAME_TRUSTSTORE_TYPE)))
            {
                rdoUseWindows.setSelected(true);
            }
            else
            {
                rdoUseJava.setSelected(true);
            }
        }

        // revocation options
        JPanel pnlRevocation = new TransparentPanel(new GridLayout(2, 1));
        pnlRevocation.setBorder(BorderFactory.createTitledBorder(
            R.getI18NString("plugin.certconfig.REVOCATION_TITLE")));
        oldPanel.add(pnlRevocation);

        chkEnableRevocationCheck = new SIPCommCheckBox(
            R.getI18NString("plugin.certconfig.REVOCATION_CHECK_ENABLED"));
        chkEnableRevocationCheck.addActionListener(this);
        chkEnableRevocationCheck.setSelected(
            "true".equals(
                System.getProperty("com.sun.net.ssl.checkRevocation")));
        pnlRevocation.add(chkEnableRevocationCheck);

        chkEnableOcsp = new SIPCommCheckBox(
            R.getI18NString("plugin.certconfig.REVOCATION_OCSP_ENABLED"));
        chkEnableOcsp.addActionListener(this);
        chkEnableOcsp.setSelected(
            "true".equals(Security.getProperty("ocsp.enable")));
        chkEnableOcsp.setEnabled(chkEnableRevocationCheck.isSelected());
        pnlRevocation.add(chkEnableOcsp);

        // Client certificate authentication list
        JPanel pnlCertList = new TransparentPanel(new BorderLayout());
        pnlCertList.setBorder(BorderFactory.createTitledBorder(
            R.getI18NString("plugin.certconfig.CERT_LIST_TITLE")));
        tabbedPane.add("Client auth", pnlCertList);

        JLabel lblNote = new JLabel();
        lblNote.setText(
            R.getI18NString("plugin.certconfig.CERT_LIST_DESCRIPTION"));
        lblNote.setBorder(new EmptyBorder(7, 7, 7, 7));
        pnlCertList.add(lblNote, BorderLayout.NORTH);

        tblCertList = new JTable();
        tblCertList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tblCertList.getSelectionModel().addListSelectionListener(this);
        tblCertList.setModel(model);
        pnlCertList.add(new JScrollPane(tblCertList), BorderLayout.CENTER);

        TransparentPanel buttons = new TransparentPanel();
        buttons.setLayout(new FlowLayout(FlowLayout.RIGHT));
        pnlCertList.add(buttons, BorderLayout.SOUTH);

        cmdAdd = new JButton();
        cmdAdd.setText(R.getI18NString("service.gui.ADD"));
        cmdAdd.addActionListener(this);
        buttons.add(cmdAdd);

        cmdRemove = new JButton();
        cmdRemove.setText(R.getI18NString("service.gui.REMOVE"));
        cmdRemove.addActionListener(this);
        buttons.add(cmdRemove);

        cmdEdit = new JButton();
        cmdEdit.setText(R.getI18NString("service.gui.EDIT"));
        cmdEdit.addActionListener(this);
        buttons.add(cmdEdit);
        
        final String whitelistedValue 
                = CertConfigActivator.getConfigService().getString(
                        CertificateService.PNAME_TLS_WHITELISTED_CIPHERSUITES);
        final String blacklistedValue 
                = CertConfigActivator.getConfigService().getString(
                        CertificateService.PNAME_TLS_BLACKLISTED_CIPHERSUITES);
        final String orderingValue 
                = CertConfigActivator.getConfigService().getString(
                        CertificateService.PNAME_TLS_CIPHERSUITES_ORDER);

        Set<String> blacklisted = new HashSet<String>(blacklistedValue == null
                ? Collections.<String>emptyList()
                : Arrays.asList(blacklistedValue.split(",")));

        Set<String> whitelisted = new HashSet<String>(whitelistedValue == null
                ? Collections.<String>emptyList() 
                : Arrays.asList(whitelistedValue.split(",")));

        java.util.List<String> ordering = new LinkedList<String>(
                orderingValue == null 
                        ? Collections.<String>emptyList() 
                        : Arrays.asList(orderingValue.split(",")));

        java.util.List<String> defaultSuiteList;
        Set<String> supportedSuiteList;

        SSLContext sslContext;
        try {
            sslContext = CertConfigActivator.getCertService().getSSLContext();
            defaultSuiteList = new LinkedList<String>(Arrays.asList(
                    sslContext.getDefaultSSLParameters().getCipherSuites()));
            supportedSuiteList = new HashSet<String>(Arrays.asList(
                    sslContext.getSupportedSSLParameters().getCipherSuites()));
        } catch (GeneralSecurityException ex) {
            logger.error("Unable to get TLS parameters", ex);
            defaultSuiteList = Collections.emptyList();
            supportedSuiteList = Collections.emptySet();
        }
                
        cipherPanel = new CipherSuitesPanel(defaultSuiteList, 
                new LinkedList<String>(supportedSuiteList), 
                new LinkedList<String>(blacklisted), 
                new LinkedList<String>(whitelisted), 
                Arrays.<String>asList(), 
                ordering);
        cipherPanel.addConfigurationChangedListener(this);
        tabbedPane.add("Cipher Suites", cipherPanel);
        add(tabbedPane);
    }

    // ------------------------------------------------------------------------
    // event handling
    // ------------------------------------------------------------------------
    public void valueChanged(ListSelectionEvent e)
    {
        int row = tblCertList.getSelectedRow();
        cmdRemove.setEnabled(row > -1);
        cmdEdit.setEnabled(row > -1);
    }

    public void actionPerformed(ActionEvent e)
    {
        if (e.getSource() == cmdAdd)
        {
            CertificateConfigEntry newEntry = new CertificateConfigEntry();
            CertConfigEntryDialog dlg = new CertConfigEntryDialog(newEntry);
            if (dlg.showDialog())
                CertConfigActivator.getCertService()
                    .setClientAuthCertificateConfig(newEntry);
        }
        if (e.getSource() == cmdRemove)
        {
            CertConfigActivator.getCertService()
                .removeClientAuthCertificateConfig(
                    model.getItem(tblCertList.getSelectedRow()).getId());
        }
        if (e.getSource() == cmdEdit)
        {
            CertificateConfigEntry entry =
                model.getItem(tblCertList.getSelectedRow());
            CertConfigEntryDialog dlg = new CertConfigEntryDialog(entry);
            if (dlg.showDialog())
                CertConfigActivator.getCertService()
                    .setClientAuthCertificateConfig(entry);
        }
        if (e.getSource() == rdoUseJava)
        {
            CertConfigActivator.getConfigService().setProperty(
                CertificateService.PNAME_TRUSTSTORE_TYPE,
                "meta:default");
            CertConfigActivator.getConfigService().removeProperty(
                CertificateService.PNAME_TRUSTSTORE_FILE);
            CertConfigActivator.getCredService().removePassword(
                CertificateService.PNAME_TRUSTSTORE_PASSWORD);
        }
        if (e.getSource() == rdoUseWindows)
        {
            CertConfigActivator.getConfigService().setProperty(
                CertificateService.PNAME_TRUSTSTORE_TYPE, "Windows-ROOT");
            CertConfigActivator.getConfigService().removeProperty(
                CertificateService.PNAME_TRUSTSTORE_FILE);
            CertConfigActivator.getCredService().removePassword(
                CertificateService.PNAME_TRUSTSTORE_PASSWORD);
        }
        if (e.getSource() == chkEnableRevocationCheck)
        {
            CertConfigActivator.getConfigService().setProperty(
                CertificateService.PNAME_REVOCATION_CHECK_ENABLED,
                chkEnableRevocationCheck.isSelected());

            String enabled = new Boolean(
                chkEnableRevocationCheck.isSelected()).toString();
            System.setProperty("com.sun.security.enableCRLDP", enabled);
            System.setProperty("com.sun.net.ssl.checkRevocation", enabled);
            chkEnableOcsp.setEnabled(chkEnableRevocationCheck.isSelected());
        }
        if (e.getSource() == chkEnableOcsp)
        {
            CertConfigActivator.getConfigService().setProperty(
                CertificateService.PNAME_OCSP_ENABLED,
                chkEnableOcsp.isSelected());

            Security.setProperty("ocsp.enable",
                new Boolean(chkEnableOcsp.isSelected()).toString());
        }
        if (e.getSource() == cipherPanel)
        {
            CertConfigActivator.getConfigService().setProperty(
                    CertificateService.PNAME_TLS_WHITELISTED_CIPHERSUITES, 
                    toString(cipherPanel.getWhiteList()));
            CertConfigActivator.getConfigService().setProperty(
                    CertificateService.PNAME_TLS_BLACKLISTED_CIPHERSUITES, 
                    toString(cipherPanel.getBlackList()));
            CertConfigActivator.getConfigService().setProperty(
                    CertificateService.PNAME_TLS_CIPHERSUITES_ORDER, 
                    toString(cipherPanel.getOrderingList()));
            
        }
    }
    
    private String toString(java.util.List<String> list)
    {
        StringBuilder sb = new StringBuilder();
        Iterator<String> iterator = list.iterator();
        while (iterator.hasNext())
        {
            sb.append(iterator.next());
            if (iterator.hasNext()) {
                sb.append(",");
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------------
    // Configuration form members
    // ------------------------------------------------------------------------
    public String getTitle()
    {
        return CertConfigActivator.R.getI18NString("plugin.certconfig.TITLE");
    }

    public byte[] getIcon()
    {
        return null;
    }

    public Object getForm()
    {
        return this;
    }

    public int getIndex()
    {
        return -1;
    }

    public boolean isAdvanced()
    {
        return true;
    }

}
