package com.ourgiant.passman.gui;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;

import com.ourgiant.passman.AppPreferences;
import com.ourgiant.passman.core.AuditLog;
import com.ourgiant.passman.core.CredentialValidator;
import com.ourgiant.passman.core.CredentialValidator.CredentialCheckResult;
import com.ourgiant.passman.core.CryptoService;
import com.ourgiant.passman.core.DatabaseStore;
import com.ourgiant.passman.core.TotpService;
import com.ourgiant.passman.model.DatabaseWrapper;
import com.ourgiant.passman.model.PasswordEntry;
import com.ourgiant.passman.util.AppVersion;
import com.ourgiant.passman.util.UpdateChecker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.List;
import javax.crypto.SecretKey;
import java.time.*;
import java.time.format.DateTimeFormatter;

/**
 * FIPS-Compliant Password Manager with TOTP MFA
 *
 * Security Features:
 * - AES-256-GCM encryption for individual passwords
 * - AES-256-GCM encryption for database file
 * - PBKDF2 key derivation (FIPS 140-2 compliant)
 * - Master password + PIN authentication
 * - TOTP-based Multi-Factor Authentication
 * - Common PIN for password retrieval
 * - Auto-deletion after failed attempts
 * - Auto-lock after inactivity
 * - Secure memory clearing
 */
public class PasswordManagerFrame extends JFrame {

    private static final Logger logger = LoggerFactory.getLogger(PasswordManagerFrame.class);

    private static final String DB_FILE = DatabaseStore.DB_FILE;
    private static final int AUTO_LOCK_MINUTES = 5;
    private static final int MAX_ATTEMPTS = 3;

    private final AppPreferences preferences = new AppPreferences();

    // Security state
    private SecretKey masterKey;
    private char[] commonPin;
    private String totpSecret;
    private int failedPinAttempts = 0;
    private int failedLoginAttempts = 0;
    private javax.swing.Timer autoLockTimer;
    private boolean isLocked = false;

    // Data
    private List<PasswordEntry> passwords;
    private PasswordEntry currentEntry;

    // UI Components
    private JPanel mainPanel;
    private JPanel loginPanel;
    private JTextField locationField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton saveButton;
    private JButton copyButton;
    private JButton generateButton;
    private JButton newButton;
    private JButton deleteButton;
    private JTable passwordTable;
    private DefaultTableModel tableModel;
    private JLabel statusLabel;
    private JProgressBar strengthBar;
    private JLabel strengthLabel;

    private Image createAppIcon() {
        BufferedImage icon = new BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = icon.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2d.setColor(new Color(70, 130, 180));
        g2d.fillRect(0, 0, 16, 16);
        g2d.setColor(Color.WHITE);
        g2d.setFont(new Font("Arial", Font.BOLD, 10));
        g2d.drawString("P", 5, 12);
        g2d.dispose();
        return icon;
    }

    private void setupMenuBar() {
        JMenuBar menuBar = new JMenuBar();

        JMenu fileMenu = new JMenu("File");
        fileMenu.setMnemonic(KeyEvent.VK_F);

        JMenuItem totpItem = new JMenuItem("View TOTP Setup");
        totpItem.addActionListener(e -> showTOTPSetup());
        fileMenu.add(totpItem);

        fileMenu.addSeparator();

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q,
            Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        exitItem.addActionListener(e -> System.exit(0));
        fileMenu.add(exitItem);

        menuBar.add(fileMenu);

        JMenu helpMenu = new JMenu("Help");
        helpMenu.setMnemonic(KeyEvent.VK_H);

        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(e -> new AboutDialog(this).setVisible(true));
        helpMenu.add(aboutItem);

        menuBar.add(helpMenu);

        setJMenuBar(menuBar);
    }

    /**
     * Silent unless there's actually something to say: no UI at all if up to date or the check
     * fails, and only once per newly-released version (not once per launch) if there's an
     * update — otherwise a known update sitting unapplied would pop this on every single
     * startup. A user can still always check manually via Help > About regardless of this
     * state. This is the app's only outbound network call, fully isolated from the vault/crypto
     * code paths: a plain GET to the public GitHub releases API, nothing derived from the
     * master password, PIN, TOTP secret, or stored entries.
     */
    private void checkForUpdateAndNotifyIfNewer() {
        SwingWorker<Optional<UpdateChecker.ReleaseInfo>, Void> worker = new SwingWorker<>() {
            @Override
            protected Optional<UpdateChecker.ReleaseInfo> doInBackground() {
                return UpdateChecker.fetchLatestRelease();
            }

            @Override
            protected void done() {
                Optional<UpdateChecker.ReleaseInfo> release;
                try {
                    release = get();
                } catch (Exception e) {
                    logger.warn("Silent startup update check failed", e);
                    return;
                }
                if (release.isEmpty()) {
                    return;
                }
                UpdateChecker.ReleaseInfo info = release.get();
                if (!UpdateChecker.isNewerVersion(info.version(), AppVersion.resolve())) {
                    return;
                }
                if (info.version().equals(preferences.getLastNotifiedUpdateVersion())) {
                    return;
                }
                preferences.setLastNotifiedUpdateVersion(info.version());
                new AboutDialog(PasswordManagerFrame.this, info).setVisible(true);
            }
        };
        worker.execute();
    }

    public PasswordManagerFrame() {
        setTitle("FIPS-Compliant Password Manager with TOTP MFA v" + AppVersion.resolve());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 650);
        setLocationRelativeTo(null);

        passwords = new ArrayList<>();
        initializeUI();
        showLoginDialog();
        setupMenuBar();

        try {
            setIconImage(createAppIcon());
        } catch (Exception e) {
            // Ignore if icon creation fails
        }

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                secureClearMemory("closed");
            }
        });

        checkForUpdateAndNotifyIfNewer();

        setVisible(true);
    }

    private void initializeUI() {
        Font uiFont = new Font("SansSerif", Font.PLAIN, 14);

        UIManager.put("Label.font", uiFont);
        UIManager.put("Button.font", uiFont);
        UIManager.put("TextField.font", uiFont);
        UIManager.put("PasswordField.font", uiFont);
        UIManager.put("Table.font", uiFont);
        UIManager.put("ProgressBar.font", uiFont);
        UIManager.put("TitledBorder.font", uiFont);

        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("Password Entry"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Location:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        locationField = new JTextField(20);
        formPanel.add(locationField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        formPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        usernameField = new JTextField(20);
        formPanel.add(usernameField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        formPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        passwordField = new JPasswordField(20);
        passwordField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                updatePasswordStrength();
            }
        });
        formPanel.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        formPanel.add(new JLabel("Strength:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel strengthPanel = new JPanel(new BorderLayout(5, 0));
        strengthBar = new JProgressBar(0, 100);
        strengthBar.setStringPainted(true);
        strengthLabel = new JLabel("None");
        strengthPanel.add(strengthBar, BorderLayout.CENTER);
        strengthPanel.add(strengthLabel, BorderLayout.EAST);
        formPanel.add(strengthPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        generateButton = new JButton("Generate Password");
        generateButton.addActionListener(e -> generateStrongPassword());
        buttonPanel.add(generateButton);

        saveButton = new JButton("Save");
        saveButton.addActionListener(e -> saveCurrentEntry());
        buttonPanel.add(saveButton);

        copyButton = new JButton("Copy to Clipboard");
        copyButton.addActionListener(e -> copyPasswordToClipboard());
        buttonPanel.add(copyButton);

        newButton = new JButton("New Entry");
        newButton.addActionListener(e -> clearForm());
        buttonPanel.add(newButton);

        deleteButton = new JButton("Delete");
        deleteButton.addActionListener(e -> deleteCurrentEntry());
        buttonPanel.add(deleteButton);

        formPanel.add(buttonPanel, gbc);

        mainPanel.add(formPanel, BorderLayout.NORTH);

        String[] columns = {"Location", "Username", "Created", "Modified"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        passwordTable = new JTable(tableModel);
        passwordTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        passwordTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    loadSelectedEntry();
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(passwordTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Stored Passwords"));
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        statusLabel = new JLabel("Ready");
        statusLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
        bottomPanel.add(statusLabel, BorderLayout.WEST);

        JPanel lockPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton lockButton = new JButton("Lock");
        lockButton.addActionListener(e -> lockApplication());
        lockPanel.add(lockButton);

        JButton backupButton = new JButton("Backup");
        backupButton.addActionListener(e -> backupDatabase());
        lockPanel.add(backupButton);

        JButton restoreButton = new JButton("Restore");
        restoreButton.addActionListener(e -> restoreDatabase());
        lockPanel.add(restoreButton);

        bottomPanel.add(lockPanel, BorderLayout.EAST);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        add(mainPanel);
        resetAutoLockTimer();
    }

    private void showLoginDialog() {
        mainPanel.setVisible(false);

        loginPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        boolean dbExists = Files.exists(Paths.get(DB_FILE).normalize());
        String title = dbExists ? "Unlock Password Manager" : "Setup Password Manager";

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        loginPanel.add(titleLabel, gbc);

        gbc.gridwidth = 1;
        gbc.gridy++;
        loginPanel.add(new JLabel("Master Password:"), gbc);
        gbc.gridx = 1;
        JPasswordField masterPasswordField = new JPasswordField(20);
        loginPanel.add(masterPasswordField, gbc);

        gbc.gridx = 0; gbc.gridy++;
        loginPanel.add(new JLabel("PIN (4-9 digits):"), gbc);
        gbc.gridx = 1;
        JPasswordField pinField = new JPasswordField(20);
        loginPanel.add(pinField, gbc);

        JPasswordField confirmPasswordField = null;
        JPasswordField confirmPinField = null;

        if (!dbExists) {
            gbc.gridx = 0; gbc.gridy++;
            loginPanel.add(new JLabel("Confirm Password:"), gbc);
            gbc.gridx = 1;
            confirmPasswordField = new JPasswordField(20);
            loginPanel.add(confirmPasswordField, gbc);

            gbc.gridx = 0; gbc.gridy++;
            loginPanel.add(new JLabel("Confirm PIN:"), gbc);
            gbc.gridx = 1;
            confirmPinField = new JPasswordField(20);
            loginPanel.add(confirmPinField, gbc);
        } else {
            // Only show TOTP field for existing database
            gbc.gridx = 0; gbc.gridy++;
            loginPanel.add(new JLabel("TOTP Code:"), gbc);
            gbc.gridx = 1;
            JTextField totpField = new JTextField(20);
            loginPanel.add(totpField, gbc);
        }

        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        JButton loginButton = new JButton(dbExists ? "Unlock" : "Create");
        JPasswordField finalConfirmPasswordField = confirmPasswordField;
        JPasswordField finalConfirmPinField = confirmPinField;

        loginButton.addActionListener(e -> {
            if (dbExists) {
                // Find the TOTP field
                JTextField totpField = null;
                for (Component comp : loginPanel.getComponents()) {
                    if (comp instanceof JTextField && !(comp instanceof JPasswordField)) {
                        totpField = (JTextField) comp;
                        break;
                    }
                }
                String totpCode = totpField != null ? totpField.getText().trim() : "";

                attemptLogin(
                    masterPasswordField.getPassword(),
                    pinField.getPassword(),
                    totpCode
                );
            } else {
                attemptSetup(
                    masterPasswordField.getPassword(),
                    pinField.getPassword(),
                    finalConfirmPasswordField.getPassword(),
                    finalConfirmPinField.getPassword(),
                    "" // TOTP code not needed for setup
                );
            }
        });

        loginPanel.add(loginButton, gbc);

        add(loginPanel);
        revalidate();
        repaint();
    }

    private void attemptSetup(char[] password, char[] pin, char[] confirmPassword, char[] confirmPin, String totpCode) {

        CredentialCheckResult result = CredentialValidator.validateCredentials(password, confirmPassword, pin, confirmPin, 16); // 16-bit entropy for PIN
        if (!result.valid) {
            JOptionPane.showMessageDialog(this, result.message, "Error", JOptionPane.ERROR_MESSAGE);
            Arrays.fill(password, '\0');
            Arrays.fill(confirmPassword, '\0');
            Arrays.fill(pin, '\0');
            Arrays.fill(confirmPin, '\0');
            return;
        }
        Arrays.fill(confirmPassword, '\0');
        Arrays.fill(confirmPin, '\0');

        try {
            // Generate TOTP secret
            totpSecret = TotpService.generateTOTPSecret();

            // Show setup dialog and get TOTP code from user
            String verifiedCode = showTOTPSetupDialogWithVerification();

            if (verifiedCode == null) {
                // User cancelled
                JOptionPane.showMessageDialog(this, "Setup cancelled.", "Cancelled", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // Verify TOTP code
            if (!TotpService.verifyTOTP(totpSecret, verifiedCode)) {
                JOptionPane.showMessageDialog(this, "Invalid TOTP code! Please try again.",
                    "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            commonPin = pin;
            byte[] salt = CryptoService.generateSalt(32);
            masterKey = CryptoService.deriveKey(password, salt);

            saveDatabase(salt);

            AuditLog.log("Database created with TOTP MFA enabled");
            remove(loginPanel);
            add(mainPanel);
            mainPanel.setVisible(true);
            revalidate();
            repaint();
            updateStatus("Database created successfully with TOTP MFA");

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Setup failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            logger.error("Setup failed", e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void attemptLogin(char[] password, char[] pin, String totpCode) {
        try {
            failedLoginAttempts++;

            if (failedLoginAttempts >= MAX_ATTEMPTS) {
                AuditLog.log("Max login attempts exceeded - deleting database");
                Files.deleteIfExists(Paths.get(DB_FILE).normalize());
                JOptionPane.showMessageDialog(this,
                    "Maximum login attempts exceeded.\nDatabase has been deleted for security.",
                    "Security Alert", JOptionPane.ERROR_MESSAGE);
                System.exit(0);
            }

            if (!isValidPinFormat(pin, 4, 6)) {
                JOptionPane.showMessageDialog(this, "Invalid PIN format!", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            byte[] salt = DatabaseStore.loadSalt();
            masterKey = CryptoService.deriveKey(password, salt);
            commonPin = pin;

            loadDatabase();

            // Verify TOTP
            if (!TotpService.verifyTOTP(totpSecret, totpCode)) {
                throw new SecurityException("Invalid TOTP code");
            }

            failedLoginAttempts = 0;
            AuditLog.log("Successful login with TOTP MFA");

            remove(loginPanel);
            add(mainPanel);
            mainPanel.setVisible(true);
            revalidate();
            repaint();
            refreshTable();
            updateStatus("Logged in successfully");

        } catch (Exception e) {
            AuditLog.log("Failed login attempt " + failedLoginAttempts + ": " + e.getMessage());
            JOptionPane.showMessageDialog(this,
                "Login failed! Attempts remaining: " + (MAX_ATTEMPTS - failedLoginAttempts),
                "Error", JOptionPane.ERROR_MESSAGE);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static boolean isValidPinFormat(char[] pin, int minLength, int maxLength) {
        if (pin.length < minLength || pin.length > maxLength) return false;
        for (char c : pin) {
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private String showTOTPSetupDialogWithVerification() {
        JDialog dialog = new JDialog(this, "TOTP Authenticator Setup", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(550, 1000);
        dialog.setLocationRelativeTo(this);

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));

        JLabel instructions = new JLabel("<html><body style='width: 480px;'>" +
            "<h2>Setup TOTP Multi-Factor Authentication</h2>" +
            "<p><b>Step 1:</b> Install an authenticator app on your phone (Google Authenticator, Authy, Microsoft Authenticator, etc.)</p>" +
            "<p><b>Step 2:</b> Select <u>\"Enter a setup key\"</u> or <u>\"Manual entry\"</u> option in your app</p>" +
            "<p><b>Step 3:</b> Enter the information below into your authenticator app</p>" +
            "<p><b>Step 4:</b> Enter the 6-digit code shown in your app below to verify setup</p>" +
            "</body></html>");
        panel.add(instructions, BorderLayout.NORTH);

        JPanel QRPanel = new JPanel(new BorderLayout(5, 5));
        QRPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.RED, 2),
            "QR Code Setup",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 13),
            Color.RED
        ));
        try {
            BufferedImage qrImage = TotpService.generateQRCode("PasswordManager", "PasswordManager", TotpService.formatSecretKey(totpSecret));

            Image scaledImage = qrImage.getScaledInstance(250, 250, Image.SCALE_SMOOTH);
            ImageIcon qrCode = new ImageIcon(scaledImage);
            JLabel qrLabel = new JLabel(qrCode);
            qrLabel.setHorizontalAlignment(JLabel.CENTER);
            qrLabel.setVerticalAlignment(JLabel.CENTER);
            QRPanel.setPreferredSize(new Dimension(260, 260));
            QRPanel.add(qrLabel, BorderLayout.CENTER);
        } catch (Exception e) {logger.warn("Failed to create QR code", e);}


        // Secret key section
        JPanel secretPanel = new JPanel(new GridLayout(5, 1, 5, 8));
        secretPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.BLUE, 2),
            "Authenticator App Setup Information",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 13),
            Color.BLUE
        ));

        JLabel accountLabel = new JLabel("Account/Name: PasswordManager");
        accountLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        secretPanel.add(accountLabel);

        JPanel keyPanel = new JPanel(new BorderLayout(5, 5));
        JLabel keyLabel = new JLabel("Secret Key:");
        keyLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        keyPanel.add(keyLabel, BorderLayout.WEST);

        JButton copySecretButton = new JButton("Copy");
        copySecretButton.addActionListener(e -> {
            StringSelection selection = new StringSelection(totpSecret);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            JOptionPane.showMessageDialog(dialog, "Secret key copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
        });
        keyPanel.add(copySecretButton, BorderLayout.EAST);
        secretPanel.add(keyPanel);

        JTextField secretField = new JTextField(TotpService.formatSecretKey(totpSecret));
        secretField.setEditable(false);
        secretField.setFont(new Font("Monospaced", Font.BOLD, 16));
        secretField.setBackground(new Color(255, 255, 200));
        keyPanel.add(secretField, BorderLayout.CENTER);

        JLabel typeLabel = new JLabel("Type: Time-based (TOTP)");
        typeLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        secretPanel.add(typeLabel);

        JLabel detailsLabel = new JLabel("Settings: Algorithm = SHA-1, Digits = 6, Period = 30 seconds");
        detailsLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        secretPanel.add(detailsLabel);

        panel.add(secretPanel, BorderLayout.CENTER);

        // TOTP verification section
        JPanel verifyPanel = new JPanel(new BorderLayout(10, 10));
        verifyPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GREEN.darker(), 2),
            "Verify Setup",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 13),
            Color.GREEN.darker()
        ));

        JLabel verifyLabel = new JLabel("Enter the 6-digit code from your authenticator app:");
        verifyLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        verifyPanel.add(verifyLabel, BorderLayout.NORTH);

        JTextField totpCodeField = new JTextField(10);
        totpCodeField.setFont(new Font("Monospaced", Font.BOLD, 18));
        totpCodeField.setHorizontalAlignment(JTextField.CENTER);
        JPanel codePanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        codePanel.add(totpCodeField);
        verifyPanel.add(codePanel, BorderLayout.CENTER);

        panel.add(verifyPanel, BorderLayout.SOUTH);
        dialog.add(QRPanel, BorderLayout.NORTH);
        dialog.add(panel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        final String[] result = new String[1]; // To store the TOTP code

        JButton verifyButton = new JButton("Verify and Continue");
        verifyButton.addActionListener(e -> {
            String code = totpCodeField.getText().trim();
            if (code.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Please enter the TOTP code!", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            result[0] = code;
            dialog.dispose();
        });
        buttonPanel.add(verifyButton);

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> {
            result[0] = null;
            dialog.dispose();
        });
        buttonPanel.add(cancelButton);

        dialog.add(buttonPanel, BorderLayout.SOUTH);

        // Make Enter key trigger verify
        totpCodeField.addActionListener(e -> verifyButton.doClick());

        dialog.setVisible(true);

        return result[0];
    }

    private void showTOTPSetup() {
        if (totpSecret == null) {
            JOptionPane.showMessageDialog(this, "TOTP not configured!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        showTOTPSetupDialog(false);
    }

    private void showTOTPSetupDialog(boolean isInitialSetup) {
        JDialog dialog = new JDialog(this, "TOTP Authenticator Setup", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(550, 1000);
        dialog.setLocationRelativeTo(this);

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));

        JLabel instructions = new JLabel("<html><body style='width: 480px;'>" +
            "<h2>TOTP Multi-Factor Authentication</h2>" +
            "<p>Your TOTP MFA is configured. Use your authenticator app to generate codes when logging in.</p>" +
            "<p>If you need to reconfigure your authenticator app, use the information below:</p>" +
            "</body></html>");
        panel.add(instructions, BorderLayout.NORTH);

        // Secret key section
        JPanel secretPanel = new JPanel(new GridLayout(5, 1, 5, 8));
        secretPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.BLUE, 2),
            "Authenticator App Setup Information",
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 13),
            Color.BLUE
        ));

        JLabel accountLabel = new JLabel("Account/Name: PasswordManager");
        accountLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        secretPanel.add(accountLabel);

        JPanel keyPanel = new JPanel(new BorderLayout(5, 5));
        JLabel keyLabel = new JLabel("Secret Key:");
        keyLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        keyPanel.add(keyLabel, BorderLayout.WEST);

        JTextField secretField = new JTextField(TotpService.formatSecretKey(totpSecret));
        secretField.setEditable(false);
        secretField.setFont(new Font("Monospaced", Font.BOLD, 16));
        secretField.setBackground(new Color(255, 255, 200));
        keyPanel.add(secretField, BorderLayout.CENTER);

        JButton copySecretButton = new JButton("Copy");
        copySecretButton.addActionListener(e -> {
            StringSelection selection = new StringSelection(totpSecret);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            updateStatus("Secret key copied!");
            JOptionPane.showMessageDialog(dialog, "Secret key copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
        });
        keyPanel.add(copySecretButton, BorderLayout.EAST);
        secretPanel.add(keyPanel);

        JPanel QRPanel = new JPanel(new BorderLayout(5, 5));
        try {
            BufferedImage qrImage = TotpService.generateQRCode("PasswordManager", "PasswordManager", TotpService.formatSecretKey(totpSecret));
            Image scaledImage = qrImage.getScaledInstance(250, 250, Image.SCALE_SMOOTH);
            ImageIcon qrCode = new ImageIcon(scaledImage);
            JLabel qrLabel = new JLabel(qrCode);
            qrLabel.setHorizontalAlignment(JLabel.CENTER);
            qrLabel.setVerticalAlignment(JLabel.CENTER);
            QRPanel.setPreferredSize(new Dimension(260, 260));
            QRPanel.add(qrLabel, BorderLayout.CENTER);
        } catch (Exception e) {logger.warn("Failed to create QR code", e);}

        JLabel typeLabel = new JLabel("Type: Time-based (TOTP)");
        typeLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        secretPanel.add(typeLabel);

        JLabel detailsLabel = new JLabel("Settings: Algorithm = SHA-1, Digits = 6, Period = 30 seconds");
        detailsLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        secretPanel.add(detailsLabel);

        panel.add(secretPanel, BorderLayout.CENTER);

        dialog.add(panel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.add(QRPanel, BorderLayout.NORTH);
        dialog.setVisible(true);
    }

    private void generateStrongPassword() {
        resetAutoLockTimer();
        String password = generatePassword(24);
        passwordField.setText(password);
        updatePasswordStrength();
        updateStatus("Strong password generated");
    }

    private String generatePassword(int length) {
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lower = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        String all = upper + lower + digits + special;

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        password.append(upper.charAt(random.nextInt(upper.length())));
        password.append(lower.charAt(random.nextInt(lower.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(special.charAt(random.nextInt(special.length())));

        for (int i = 4; i < length; i++) {
            password.append(all.charAt(random.nextInt(all.length())));
        }

        List<Character> chars = new ArrayList<>();
        for (char c : password.toString().toCharArray()) {
            chars.add(c);
        }
        Collections.shuffle(chars, random);

        StringBuilder result = new StringBuilder();
        for (char c : chars) {
            result.append(c);
        }

        return result.toString();
    }

    private void saveCurrentEntry() {
        resetAutoLockTimer();

        String location = locationField.getText().trim();
        String username = usernameField.getText().trim();
        char[] password = passwordField.getPassword();

        if (location.isEmpty() || username.isEmpty() || password.length == 0) {
            JOptionPane.showMessageDialog(this, "Please fill all fields!", "Error", JOptionPane.ERROR_MESSAGE);
            Arrays.fill(password, '\0');
            return;
        }

        try {
            if (currentEntry == null) {
                PasswordEntry entry = new PasswordEntry();
                entry.id = UUID.randomUUID().toString();
                entry.location = location;
                entry.username = username;
                entry.encryptedPassword = CryptoService.encryptPassword(password, masterKey);
                entry.created = LocalDateTime.now();
                entry.modified = LocalDateTime.now();

                passwords.add(entry);
                AuditLog.log("Created entry: " + location);
            } else {
                currentEntry.location = location;
                currentEntry.username = username;
                currentEntry.encryptedPassword = CryptoService.encryptPassword(password, masterKey);
                currentEntry.modified = LocalDateTime.now();
                AuditLog.log("Updated entry: " + location);
            }

            saveDatabase(null);
            refreshTable();
            clearForm();
            updateStatus("Entry saved successfully");

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Save failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            logger.error("Save failed", e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void loadSelectedEntry() {
        resetAutoLockTimer();

        int row = passwordTable.getSelectedRow();
        if (row < 0) return;

        String location = (String) tableModel.getValueAt(row, 0);
        PasswordEntry entry = passwords.stream()
            .filter(e -> e.location.equals(location))
            .findFirst()
            .orElse(null);

        if (entry == null) return;

        JPasswordField pinField = new JPasswordField();
        JPanel panel = new JPanel(new BorderLayout());
        SwingUtilities.invokeLater(() -> pinField.requestFocusInWindow());
        panel.add(new JLabel("Enter PIN to unlock password:"), BorderLayout.NORTH);
        panel.add(pinField, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(
            this,
            panel,
            "PIN Entry",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        );

        if (result != JOptionPane.OK_OPTION) return;

        char[] pin = pinField.getPassword();
        boolean pinMatches = CryptoService.constantTimeEquals(pin, commonPin);
        Arrays.fill(pin, '\0');

        if (!pinMatches) {
            failedPinAttempts++;
            AuditLog.log("Failed PIN attempt for: " + entry.location + " (attempt " + failedPinAttempts + ")");

            if (failedPinAttempts >= MAX_ATTEMPTS) {
                passwords.remove(entry);
                try {
                    saveDatabase(null);
                } catch (Exception e) {
                    logger.error("Failed to save database after removing entry for exceeded PIN attempts", e);
                }
                refreshTable();
                JOptionPane.showMessageDialog(this,
                    "Maximum PIN attempts exceeded.\nEntry has been deleted for security.",
                    "Security Alert", JOptionPane.ERROR_MESSAGE);
                failedPinAttempts = 0;
            } else {
                JOptionPane.showMessageDialog(this,
                    "Incorrect PIN! Attempts remaining: " + (MAX_ATTEMPTS - failedPinAttempts),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
            return;
        }

        failedPinAttempts = 0;

        try {
            String password = CryptoService.decryptPassword(entry.encryptedPassword, masterKey);

            locationField.setText(entry.location);
            usernameField.setText(entry.username);
            passwordField.setText(password);
            currentEntry = entry;

            updatePasswordStrength();
            updateStatus("Entry loaded: " + entry.location);
            AuditLog.log("Accessed entry: " + entry.location);

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Failed to decrypt password: " + e.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
            logger.error("Failed to decrypt password", e);
        }
    }

    private void deleteCurrentEntry() {
        resetAutoLockTimer();

        if (currentEntry == null) {
            JOptionPane.showMessageDialog(this, "No entry selected!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to delete this entry?",
            "Confirm Delete", JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            try {
                AuditLog.log("Deleted entry: " + currentEntry.location);
                passwords.remove(currentEntry);
                saveDatabase(null);
                refreshTable();
                clearForm();
                updateStatus("Entry deleted");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Delete failed: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void copyPasswordToClipboard() {
        resetAutoLockTimer();

        String password = new String(passwordField.getPassword());
        if (password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No password to copy!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        StringSelection selection = new StringSelection(password);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, selection);

        updateStatus("Password copied to clipboard");

        javax.swing.Timer clearTimer = new javax.swing.Timer(30000, e -> {
            try {
                Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
                cb.setContents(new StringSelection(""), null);
            } catch (Exception ex) {
                // Ignore
            }
        });
        clearTimer.setRepeats(false);
        clearTimer.start();
    }

    private void clearForm() {
        locationField.setText("");
        usernameField.setText("");
        passwordField.setText("");
        currentEntry = null;
        updatePasswordStrength();
        updateStatus("Form cleared");
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

        for (PasswordEntry entry : passwords) {
            tableModel.addRow(new Object[]{
                entry.location,
                entry.username,
                entry.created.format(formatter),
                entry.modified.format(formatter)
            });
        }
    }

    private void updatePasswordStrength() {
        String password = new String(passwordField.getPassword());
        if (password.isEmpty()) {
            strengthBar.setValue(0);
            strengthBar.setForeground(Color.GRAY);
            strengthLabel.setText("None");
            return;
        }

        int strength = 0;
        if (password.length() >= 8) strength += 20;
        if (password.length() >= 12) strength += 10;
        if (password.length() >= 16) strength += 10;
        if (password.matches(".*[a-z].*")) strength += 15;
        if (password.matches(".*[A-Z].*")) strength += 15;
        if (password.matches(".*\\d.*")) strength += 15;
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?].*")) strength += 15;

        strengthBar.setValue(strength);

        if (strength < 40) {
            strengthBar.setForeground(Color.RED);
            strengthLabel.setText("Weak");
        } else if (strength < 70) {
            strengthBar.setForeground(Color.ORANGE);
            strengthLabel.setText("Medium");
        } else {
            strengthBar.setForeground(Color.GREEN);
            strengthLabel.setText("Strong");
        }
    }

    private void updateStatus(String message) {
        statusLabel.setText(message);
    }

    private void lockApplication() {
        isLocked = true;
        mainPanel.setVisible(false);
        if (autoLockTimer != null) {
            autoLockTimer.stop();
        }
        secureClearMemory("locked");
        showLoginDialog();
        AuditLog.log("Application locked");
    }

    private void resetAutoLockTimer() {
        if (autoLockTimer != null) {
            autoLockTimer.stop();
        }

        autoLockTimer = new javax.swing.Timer(AUTO_LOCK_MINUTES * 60 * 1000, e -> {
            if (!isLocked) {
                lockApplication();
                JOptionPane.showMessageDialog(this,
                    "Application locked due to inactivity.",
                    "Auto-Lock", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        autoLockTimer.setRepeats(false);
        autoLockTimer.start();
    }

    private void backupDatabase() {
        resetAutoLockTimer();

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Backup");
        chooser.setSelectedFile(new File("passwords_backup_" +
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".enc"));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                Files.copy(Paths.get(DB_FILE).normalize(), chooser.getSelectedFile().toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
                updateStatus("Backup created successfully");
                AuditLog.log("Database backed up");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Backup failed: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void restoreDatabase() {
        resetAutoLockTimer();

        int confirm = JOptionPane.showConfirmDialog(this,
            "Restoring will replace current database. Continue?",
            "Confirm Restore", JOptionPane.YES_NO_OPTION);

        if (confirm != JOptionPane.YES_OPTION) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Backup File");

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                Files.copy(chooser.getSelectedFile().toPath(), Paths.get(DB_FILE).normalize(),
                    StandardCopyOption.REPLACE_EXISTING);
                loadDatabase();
                refreshTable();
                updateStatus("Database restored successfully");
                AuditLog.log("Database restored");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Restore failed: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void saveDatabase(byte[] salt) throws Exception {
        DatabaseStore.saveDatabase(salt, masterKey, passwords, totpSecret);
    }

    private void loadDatabase() throws Exception {
        DatabaseWrapper wrapper = DatabaseStore.loadDatabase(masterKey);
        passwords = wrapper.getPasswords();
        totpSecret = wrapper.getTotpSecret();
    }

    private void secureClearMemory(String reason) {
        if (masterKey != null) {
            try {
                byte[] keyBytes = masterKey.getEncoded();
                Arrays.fill(keyBytes, (byte) 0);
            } catch (Exception e) {
                logger.error("Failed to zero master key material", e);
            }
            masterKey = null;
        }

        if (commonPin != null) {
            Arrays.fill(commonPin, '\0');
            commonPin = null;
        }

        if (totpSecret != null) {
            char[] secretChars = totpSecret.toCharArray();
            Arrays.fill(secretChars, '0');
            totpSecret = null;
        }

        if (passwordField != null) {
            passwordField.setText("");
        }

        AuditLog.log("Memory cleared (" + reason + ")");
    }
}
