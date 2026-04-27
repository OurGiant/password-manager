package com.ourgiant.passman;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.nio.file.attribute.*;




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
public class PasswordManager extends JFrame {
    
    // Constants
    private static final Path DB_PATH = getDatabaseFilePath();
    private static final String DB_FILE = DB_PATH.toString();
    private static final String LOG_FILE = "audit.log";
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final int KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AUTO_LOCK_MINUTES = 5;
    private static final int MAX_ATTEMPTS = 3;
    private static final int TOTP_DIGITS = 6;
    private static final int TOTP_PERIOD = 30; // seconds
    
    // Security state
    private SecretKey masterKey;
    private String commonPin;
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
    
    public static void main(String[] args) {
        // Ensure Java Cryptography Extension (JCE) is available
        try {
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            if (maxKeyLen < 256) {
                JOptionPane.showMessageDialog(null, 
                    "Unlimited Strength JCE required for AES-256.\nPlease install JCE Unlimited Strength Jurisdiction Policy Files.",
                    "Cryptography Error", JOptionPane.ERROR_MESSAGE);
                System.exit(1);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new PasswordManager();
        });
    }

    private Image createAppIcon() {
        BufferedImage icon = new BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = icon.createGraphics();
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
        setJMenuBar(menuBar);
    }
    
    public PasswordManager() {
        setTitle("FIPS-Compliant Password Manager with TOTP MFA");
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
                secureClearMemory();
            }
        });
        
        setVisible(true);
    }

    private static Path getDatabaseFilePath() {
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData == null || localAppData.isBlank()) {
            localAppData = Paths.get(System.getProperty("user.home"), "AppData", "Local").toString();
        }

        Path dir = Paths.get(localAppData, "JavaPassManager");
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create data directory: " + dir, e);
        }
        
        File db_file = (dir.resolve("passwords.enc")).toFile();
        String canonicalPath = "";
        try {
            canonicalPath = db_file.getCanonicalPath();
            if (!canonicalPath.startsWith(FileSystems.getDefault().getSeparator())) {}
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create database: " + canonicalPath, e);
        }


        return dir.resolve("passwords.enc");
    }

    private static void restrictToCurrentUser(Path path) {
        try {
            AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (view == null) {
                System.err.println("ACLs not supported on this filesystem.");
                return;
            }

            UserPrincipalLookupService lookupService = path.getFileSystem().getUserPrincipalLookupService();
            UserPrincipal user = lookupService.lookupPrincipalByName(System.getProperty("user.name"));

            List<AclEntry> acl = new ArrayList<>();
            Set<AclEntryPermission> perms = EnumSet.of(
                    AclEntryPermission.READ_DATA,
                    AclEntryPermission.WRITE_DATA,
                    AclEntryPermission.APPEND_DATA,
                    AclEntryPermission.READ_ATTRIBUTES,
                    AclEntryPermission.WRITE_ATTRIBUTES,
                    AclEntryPermission.READ_ACL,
                    AclEntryPermission.WRITE_ACL,
                    AclEntryPermission.WRITE_OWNER,
                    AclEntryPermission.DELETE
            );

            acl.add(AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(user)
                    .setPermissions(perms)
                    .build());

            try {
                UserPrincipal system = lookupService.lookupPrincipalByName("SYSTEM");
                acl.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(system)
                        .setPermissions(perms)
                        .build());
            } catch (IOException e) {
                System.err.println("SYSTEM principal not found: " + e);
            }

            try {
                UserPrincipal admins = lookupService.lookupPrincipalByName("Administrators");
                acl.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(admins)
                        .setPermissions(perms)
                        .build());
            } catch (IOException e) {
                System.err.println("Administrators principal not found: " + e);
            }

            view.setAcl(acl);
        } catch (Exception e) {
            System.err.println("Warning: failed to set ACL for " + path + ": " + e);
        }
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
                    new String(masterPasswordField.getPassword()),
                    new String(pinField.getPassword()),
                    totpCode
                );
            } else {
                attemptSetup(
                    new String(masterPasswordField.getPassword()),
                    new String(pinField.getPassword()),
                    new String(finalConfirmPasswordField.getPassword()),
                    new String(finalConfirmPinField.getPassword()),
                    "" // TOTP code not needed for setup
                );
            }
        });

        loginPanel.add(loginButton, gbc);

        add(loginPanel);
        revalidate();
        repaint();
    }

    private void attemptSetup(String password, String pin, String confirmPassword, String confirmPin, String totpCode) {

        CredentialCheckResult result = validateCredentials(password, confirmPassword, pin, confirmPin, 16); // 16-bit entropy for PIN
        if (!result.valid) {
            JOptionPane.showMessageDialog(this, result.message, "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        
        try {
            // Generate TOTP secret
            totpSecret = generateTOTPSecret();
            
            // Show setup dialog and get TOTP code from user
            String verifiedCode = showTOTPSetupDialogWithVerification();
            
            if (verifiedCode == null) {
                // User cancelled
                JOptionPane.showMessageDialog(this, "Setup cancelled.", "Cancelled", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            // Verify TOTP code
            if (!verifyTOTP(verifiedCode)) {
                JOptionPane.showMessageDialog(this, "Invalid TOTP code! Please try again.", 
                    "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            commonPin = pin;
            byte[] salt = generateSalt(32);
            masterKey = deriveKey(password, salt);
            
            saveDatabase(salt);
            
            logAudit("Database created with TOTP MFA enabled");
            remove(loginPanel);
            add(mainPanel);
            mainPanel.setVisible(true);
            revalidate();
            repaint();
            updateStatus("Database created successfully with TOTP MFA");
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Setup failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
        }
    }
    
    private void attemptLogin(String password, String pin, String totpCode) {
        try {
            failedLoginAttempts++;
            
            if (failedLoginAttempts >= MAX_ATTEMPTS) {
                logAudit("Max login attempts exceeded - deleting database");
                Files.deleteIfExists(Paths.get(DB_FILE).normalize());
                JOptionPane.showMessageDialog(this, 
                    "Maximum login attempts exceeded.\nDatabase has been deleted for security.",
                    "Security Alert", JOptionPane.ERROR_MESSAGE);
                System.exit(0);
            }
            
            if (!pin.matches("\\d{4,6}")) {
                JOptionPane.showMessageDialog(this, "Invalid PIN format!", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            byte[] salt = loadSalt();
            masterKey = deriveKey(password, salt);
            commonPin = pin;
            
            loadDatabase();
            
            // Verify TOTP
            if (!verifyTOTP(totpCode)) {
                throw new SecurityException("Invalid TOTP code");
            }
            
            failedLoginAttempts = 0;
            logAudit("Successful login with TOTP MFA");
            
            remove(loginPanel);
            add(mainPanel);
            mainPanel.setVisible(true);
            revalidate();
            repaint();
            refreshTable();
            updateStatus("Logged in successfully");
            
        } catch (Exception e) {
            logAudit("Failed login attempt " + failedLoginAttempts + ": " + e.getMessage());
            JOptionPane.showMessageDialog(this, 
                "Login failed! Attempts remaining: " + (MAX_ATTEMPTS - failedLoginAttempts),
                "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private String generateTOTPSecret() {
        byte[] buffer = new byte[20]; // 160 bits
        new SecureRandom().nextBytes(buffer);
        return base32Encode(buffer);
    }
    
    private String base32Encode(byte[] data) {
        String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(base32Chars.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        
        if (bitsLeft > 0) {
            result.append(base32Chars.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        
        return result.toString();
    }
    
    private byte[] base32Decode(String encoded) {
        String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        encoded = encoded.toUpperCase().replaceAll("[^A-Z2-7]", "");
        
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;
        
        for (char c : encoded.toCharArray()) {
            int val = base32Chars.indexOf(c);
            if (val < 0) continue;
            
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            
            if (bitsLeft >= 8) {
                result.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        
        return result.toByteArray();
    }
    
    private String generateTOTP(String secret, long timeStep) {
        try {
            byte[] key = base32Decode(secret);
            byte[] data = new byte[8];
            long value = timeStep;
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) value;
                value >>= 8;
            }
            
            SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);
            
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                        ((hash[offset + 1] & 0xFF) << 16) |
                        ((hash[offset + 2] & 0xFF) << 8) |
                        (hash[offset + 3] & 0xFF);
            
            int otp = binary % (int) Math.pow(10, TOTP_DIGITS);
            return String.format("%0" + TOTP_DIGITS + "d", otp);
            
        } catch (Exception e) {
            e.printStackTrace();
            logAudit("TOTP generation error: " + e.getMessage());
            return null;
        }
    }
    
    private boolean verifyTOTP(String code) {
        if (totpSecret == null || code == null || code.trim().isEmpty()) {
            return false;
        }
        
        // Remove any spaces or formatting from input
        code = code.trim().replaceAll("\\s+", "");
        
        // Verify it's 6 digits
        if (!code.matches("\\d{6}")) {
            logAudit("Invalid TOTP format: " + code);
            return false;
        }
        
        long currentTime = System.currentTimeMillis() / 1000 / TOTP_PERIOD;
        
        // Check current and adjacent time windows (allows for clock skew)
        for (int i = -2; i <= 2; i++) {
            String validCode = generateTOTP(totpSecret, currentTime + i);
            if (validCode != null && code.equals(validCode)) {
                logAudit("TOTP verified successfully (window offset: " + i + ")");
                return true;
            }
        }
        
        // Log what we were expecting vs what we got (for debugging)
        String expectedCurrent = generateTOTP(totpSecret, currentTime);
        logAudit("TOTP verification failed. Expected (current): " + expectedCurrent + ", Got: " + code);
        
        return false;
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
            BufferedImage qrImage = generateQRCode("PasswordManager", "PasswordManager", formatSecretKey(totpSecret));

            Image scaledImage = qrImage.getScaledInstance(250, 250, Image.SCALE_SMOOTH);
            ImageIcon qrCode = new ImageIcon(scaledImage);
            JLabel qrLabel = new JLabel(qrCode);
            qrLabel.setHorizontalAlignment(JLabel.CENTER);
            qrLabel.setVerticalAlignment(JLabel.CENTER);
            QRPanel.setPreferredSize(new Dimension(260, 260));
            QRPanel.add(qrLabel, BorderLayout.CENTER);
        } catch (Exception e) {System.out.println("Failed to create QR Code: " + e);}
               
        
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

        JTextField secretField = new JTextField(formatSecretKey(totpSecret));
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
        
        JTextField secretField = new JTextField(formatSecretKey(totpSecret));
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
            BufferedImage qrImage = generateQRCode("PasswordManager", "PasswordManager", formatSecretKey(totpSecret));
            Image scaledImage = qrImage.getScaledInstance(250, 250, Image.SCALE_SMOOTH);
            ImageIcon qrCode = new ImageIcon(scaledImage);
            JLabel qrLabel = new JLabel(qrCode);
            qrLabel.setHorizontalAlignment(JLabel.CENTER);
            qrLabel.setVerticalAlignment(JLabel.CENTER);
            QRPanel.setPreferredSize(new Dimension(260, 260));
            QRPanel.add(qrLabel, BorderLayout.CENTER);
        } catch (Exception e) {System.out.println("Failed to create QR Code: " + e);}
        
        JLabel typeLabel = new JLabel("Type: Time-based (TOTP)");
        typeLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        secretPanel.add(typeLabel);
        
        JLabel detailsLabel = new JLabel("Settings: Algorithm = SHA-1, Digits = 6, Period = 30 seconds");
        detailsLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        secretPanel.add(detailsLabel);
        
        // Add current code for debugging
        String currentCode = generateCurrentTOTP();
        JLabel debugLabel = new JLabel("<html><b>Current Expected Code (for testing):</b> <font color='red'>" + currentCode + "</font></html>");
        debugLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        secretPanel.add(debugLabel);
        
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
    
    private String generateCurrentTOTP() {
        long currentTime = System.currentTimeMillis() / 1000 / TOTP_PERIOD;
        return generateTOTP(totpSecret, currentTime);
    }
    
    private String formatSecretKey(String key) {
        // Format key with spaces every 4 characters for readability
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < key.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                formatted.append(" ");
            }
            formatted.append(key.charAt(i));
        }
        return formatted.toString();
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
        String password = new String(passwordField.getPassword());
        
        if (location.isEmpty() || username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please fill all fields!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        try {
            if (currentEntry == null) {
                PasswordEntry entry = new PasswordEntry();
                entry.id = UUID.randomUUID().toString();
                entry.location = location;
                entry.username = username;
                entry.encryptedPassword = encryptPassword(password);
                entry.created = LocalDateTime.now();
                entry.modified = LocalDateTime.now();
                
                passwords.add(entry);
                logAudit("Created entry: " + location);
            } else {
                currentEntry.location = location;
                currentEntry.username = username;
                currentEntry.encryptedPassword = encryptPassword(password);
                currentEntry.modified = LocalDateTime.now();
                logAudit("Updated entry: " + location);
            }
            
            saveDatabase(null);
            refreshTable();
            clearForm();
            updateStatus("Entry saved successfully");
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Save failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
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

        String pin = new String(pinField.getPassword());

        if (pin == null) return;
        
        if (!pin.equals(commonPin)) {
            failedPinAttempts++;
            logAudit("Failed PIN attempt for: " + entry.location + " (attempt " + failedPinAttempts + ")");
            
            if (failedPinAttempts >= MAX_ATTEMPTS) {
                passwords.remove(entry);
                try {
                    saveDatabase(null);
                } catch (Exception e) {
                    e.printStackTrace();
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
            String password = decryptPassword(entry.encryptedPassword);
            
            locationField.setText(entry.location);
            usernameField.setText(entry.username);
            passwordField.setText(password);
            currentEntry = entry;
            
            updatePasswordStrength();
            updateStatus("Entry loaded: " + entry.location);
            logAudit("Accessed entry: " + entry.location);
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Failed to decrypt password: " + e.getMessage(), 
                "Error", JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
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
                logAudit("Deleted entry: " + currentEntry.location);
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
        showLoginDialog();
        logAudit("Application locked");
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
                logAudit("Database backed up");
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
                logAudit("Database restored");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Restore failed: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    // Cryptography methods
    
    private byte[] generateSalt(final int size) {
        byte[] salt = new byte[size];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] generateIv(final int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }    
    
    private SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
    
    private byte[] encryptPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, parameterSpec);
        
        byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
        
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        
        return result;
    }
    
    private String decryptPassword(byte[] encryptedData) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encrypted = new byte[encryptedData.length - GCM_IV_LENGTH];
        
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedData, GCM_IV_LENGTH, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, parameterSpec);
        
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    
   
    private byte[] loadSalt() throws Exception {
        byte[] salt = generateSalt(32);
        try (FileInputStream fis = new FileInputStream(DB_FILE)) {
            fis.read(salt);
        }
        return salt;
    }

    private void saveDatabase(byte[] salt) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.findAndRegisterModules(); // Automatically finds jackson-datatype-jsr310
        DatabaseWrapper wrapper = new DatabaseWrapper();
        wrapper.passwords = passwords;
        wrapper.totpSecret = totpSecret;

        byte[] jsonData = mapper.writeValueAsBytes(wrapper);

        if (salt == null) {
            salt = loadSalt();
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = generateIv(12);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, gcmSpec);

        byte[] encrypted = cipher.doFinal(jsonData);

        try (FileOutputStream fos = new FileOutputStream(DB_FILE)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(encrypted);
        }
    }   

    @SuppressWarnings("unchecked")
    private void loadDatabase() throws Exception {
        final int SALT_LEN = 32;
        final int IV_LEN = 12;           // Standard for GCM
        final int GCM_TAG_LEN_BITS = 128;

        Path path = Paths.get(DB_FILE);
        if (!Files.exists(path)) {
            // no existing database file
            passwords = new ArrayList<>();
            totpSecret = null;
            return;
        }

        try (FileInputStream fis = new FileInputStream(DB_FILE)) {
            // --- Read salt and IV from file header ---
            byte[] salt = fis.readNBytes(SALT_LEN);
            if (salt.length != SALT_LEN)
                throw new IOException("Corrupted file: missing salt");

            byte[] iv = fis.readNBytes(IV_LEN);
            if (iv.length != IV_LEN)
                throw new IOException("Corrupted file: missing IV");

            // --- Initialize cipher for AES-GCM decryption ---
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LEN_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, gcmSpec);

            // --- Decrypt the rest of the file ---
            byte[] encrypted = fis.readAllBytes();
            byte[] decrypted = cipher.doFinal(encrypted);

            // --- Parse JSON into your DatabaseWrapper object ---
            ObjectMapper mapper = new ObjectMapper();
            mapper.findAndRegisterModules();  // e.g. JavaTimeModule if needed
            DatabaseWrapper wrapper = mapper.readValue(decrypted, DatabaseWrapper.class);

            // --- Assign values ---
            passwords = wrapper.passwords;
            totpSecret = wrapper.totpSecret;

        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("Decryption failed: wrong key or tampered file", e);
        }
    }

    private void logAudit(String message) {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            String logEntry = timestamp + " - " + message + "\n";
            Files.write(Paths.get(LOG_FILE), logEntry.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void secureClearMemory() {
        if (masterKey != null) {
            try {
                byte[] keyBytes = masterKey.getEncoded();
                Arrays.fill(keyBytes, (byte) 0);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        if (commonPin != null) {
            char[] pinChars = commonPin.toCharArray();
            Arrays.fill(pinChars, '0');
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
        
        logAudit("Application closed - memory cleared");
    }
    
    private static CredentialCheckResult validateCredentials(
            String password, String confirmPassword,
            String pin, String confirmPin,
            double pinMinEntropyBits) {

        // --- Password checks ---
        if (password == null || !password.equals(confirmPassword)) {
            return new CredentialCheckResult(false, "Passwords do not match!");
        }

        if (!isStrongPassword(password)) {
            return new CredentialCheckResult(false,
                "Master password must be at least 8 characters long and include upper, lower, digit, and special character.");
        }

        // --- PIN checks ---
        if (pin == null || !pin.equals(confirmPin)) {
            return new CredentialCheckResult(false, "PINs do not match!");
        }

        PinStrengthResult pinResult = checkPinStrength(pin, pinMinEntropyBits);
        if (!pinResult.isStrong) {
            return new CredentialCheckResult(false, "PIN is too weak: " + pinResult.message);
        }

        // All checks passed
        return new CredentialCheckResult(true, "Credentials are strong.");
    }

    /**
     * Check PIN strength and provide feedback
     */
    private static PinStrengthResult checkPinStrength(String pin, double minEntropyBits) {
        if (pin == null || !pin.matches("\\d{4,9}")) {
            return new PinStrengthResult(false, "PIN must be 4-9 digits.", 0);
        }

        int length = pin.length();
        double entropy = length * Math.log(10) / Math.log(2); // max entropy
        StringBuilder feedback = new StringBuilder();

        // Repeating digits
        if (pin.matches("(\\d)\\1{3,}")) {
            entropy -= 4;
            feedback.append("Avoid repeating digits (e.g., 1111). ");
        }

        // Sequential digits
        boolean hasSequence = false;
        for (int i = 0; i <= pin.length() - 4; i++) {
            int d1 = pin.charAt(i) - '0';
            int d2 = pin.charAt(i + 1) - '0';
            int d3 = pin.charAt(i + 2) - '0';
            int d4 = pin.charAt(i + 3) - '0';
            if ((d2 == d1 + 1 && d3 == d2 + 1 && d4 == d3 + 1) ||
                (d2 == d1 - 1 && d3 == d2 - 1 && d4 == d3 - 1)) {
                hasSequence = true;
                break;
            }
        }
        if (hasSequence) {
            entropy -= 4;
            feedback.append("Avoid sequences of 4 or more digits (e.g., 1234). ");
        }

        // Very common PINs
        String[] common = {"1234","1111","0000","1212","7777"};
        for (String c : common) {
            if (pin.equals(c)) {
                entropy -= 5;
                feedback.append("Avoid very common PINs. ");
                break;
            }
        }

        // Ensure non-negative entropy
        entropy = Math.max(entropy, 0);

        if (entropy < minEntropyBits) {
            if (feedback.length() == 0) feedback.append("PIN is too weak.");
            return new PinStrengthResult(false, feedback.toString(), entropy);
        }

        return new PinStrengthResult(true, "PIN is strong.", entropy);
    }

    private static boolean isStrongPassword(String password) {
        if (password == null || password.isEmpty()) return false;

        Zxcvbn zxcvbn = new Zxcvbn();
        Strength strength = zxcvbn.measure(password);

        // strength score is 0–4; 3+ is considered "strong"
        // System.err.println("Score:"+strength.getScore());
        return strength.getScore() >= 3;
    }

    private static BufferedImage generateQRCode(String issuer, String account, String secret) throws Exception {
        String algorithm = "SHA1"; // For Google Authenticator compatibility
        int digits = 6;
        int period = 30;

        // Construct the TOTP URI
        String totpUri = String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
            issuer, account, secret, issuer, algorithm, digits, period
        );

        // Generate QR code
        BitMatrix matrix = new MultiFormatWriter().encode(totpUri, BarcodeFormat.QR_CODE, 250, 250);
        return MatrixToImageWriter.toBufferedImage(matrix);
    }
    
    // Inner classes
    public static class DatabaseWrapper {
        
        @JsonProperty("passwords")
        private List<PasswordEntry> passwords;

        @JsonProperty("totpSecret")
        private String totpSecret;

        // Default constructor required for Jackson
        public DatabaseWrapper() {}

        // Getters and setters
        public List<PasswordEntry> getPasswords() {
            return passwords;
        }

        public void setPasswords(List<PasswordEntry> passwords) {
            this.passwords = passwords;
        }

        public String getTotpSecret() {
            return totpSecret;
        }

        public void setTotpSecret(String totpSecret) {
            this.totpSecret = totpSecret;
        }
    }
    
    static class PasswordEntry implements Serializable {
        private static final long serialVersionUID = 1L;

        @JsonProperty("id")
        String id;

        @JsonProperty("location")
        String location;

        @JsonProperty("username")
        String username;

        @JsonProperty("encryptedPassword")
        byte[] encryptedPassword;

        @JsonProperty("created")
        LocalDateTime created;

        @JsonProperty("modified")
        LocalDateTime modified;

        // Default constructor for Jackson
        public PasswordEntry() {}

        // Getters and setters for Jackson
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }

        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public byte[] getEncryptedPassword() { return encryptedPassword; }
        public void setEncryptedPassword(byte[] encryptedPassword) { this.encryptedPassword = encryptedPassword; }

        public LocalDateTime getCreated() { return created; }
        public void setCreated(LocalDateTime created) { this.created = created; }

        public LocalDateTime getModified() { return modified; }
        public void setModified(LocalDateTime modified) { this.modified = modified; }
    }

    public static class CredentialCheckResult {
        public final boolean valid;
        public final String message;

        public CredentialCheckResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
    }

    public static class PinStrengthResult {
        public final boolean isStrong;
        public final String message;
        public final double entropyBits;

        public PinStrengthResult(boolean isStrong, String message, double entropyBits) {
            this.isStrong = isStrong;
            this.message = message;
            this.entropyBits = entropyBits;
        }
    }

}