package com.server.avast.verisign.jarsigner;

import com.server.avast.verisign.config.properties.KeystoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.timestamp.TimestampToken;
import sun.security.tools.KeyStoreUtil;
import sun.security.util.*;
import sun.security.validator.Validator;
import sun.security.validator.ValidatorException;
import sun.security.x509.AlgorithmId;
import sun.security.x509.NetscapeCertTypeExtension;
import sun.security.tools.jarsigner.Resources;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.text.Collator;
import java.text.MessageFormat;
import java.util.*;
import java.util.Map.Entry;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.stream.Collectors;


/**
 * <p>The jarsigner utility.
 * <p>
 * The exit codes for the main method are:
 * <p>
 * 0: success
 * 1: any error that the jar cannot be signed or verified, including:
 * keystore loading error
 * TSP communication error
 * jarsigner command line error...
 * otherwise: error codes from -strict
 *
 * @author Roland Schemers
 * @author Jan Luehe
 */
public class Main {

    static final int IN_KEYSTORE = 0x01;        // signer is in keystore
    static final int NOT_ALIAS = 0x04;          // alias list is NOT empty and
    // signer is not in alias list
    static final int SIGNED_BY_ALIAS = 0x08;    // signer is in alias list
    // for i18n
    // for i18n
    private static final java.util.ResourceBundle rb = new Resources();
//            java.util.ResourceBundle.getBundle
//                    ("sun.security.tools.jarsigner.Resources");

//    private static final java.util.ResourceBundle rb = new ResourceBundle() {
//        @Override
//        protected Object handleGetObject(@NotNull String key) {
//            return key;
//        }
//
//        @NotNull
//        @Override
//        public Enumeration<String> getKeys() {
//            return Collections.emptyEnumeration();
//        }
//    };

    private static final Collator collator = Collator.getInstance();
    private static final String NONE = "NONE";
    private static final String P11KEYSTORE = "PKCS11";
    private static final long SIX_MONTHS = 180 * 24 * 60 * 60 * 1000L; //milliseconds
    private static final long ONE_YEAR = 366 * 24 * 60 * 60 * 1000L;
    private static final DisabledAlgorithmConstraints DISABLED_CHECK =
            new DisabledAlgorithmConstraints(
                    DisabledAlgorithmConstraints.PROPERTY_JAR_DISABLED_ALGS);
    private static final Set<CryptoPrimitive> DIGEST_PRIMITIVE_SET = Collections
            .unmodifiableSet(EnumSet.of(CryptoPrimitive.MESSAGE_DIGEST));
    private static final Set<CryptoPrimitive> SIG_PRIMITIVE_SET = Collections
            .unmodifiableSet(EnumSet.of(CryptoPrimitive.SIGNATURE));
    private static final String SPACE = "     ";
    private static MessageFormat validityTimeForm = null;
    private static MessageFormat notYetTimeForm = null;
    private static MessageFormat expiredTimeForm = null;
    private static MessageFormat expiringTimeForm = null;
    private static MessageFormat signTimeForm = null;
    // or the default keystore, never null

    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    static {
        // this is for case insensitive string comparisions
        collator.setStrength(Collator.PRIMARY);
    }

    PrivateKey privateKey;          // private key
    KeyStore store;                 // the keystore specified by -keystore
    String keystore; // key store file
    boolean nullStream = false; // null keystore input stream (NONE)
    boolean token = false; // token-based keystore
    String jarfile;  // jar files to sign or verify
    String alias;    // alias to sign jar with
    List<String> ckaliases = new ArrayList<>(1); // aliases in -verify
    char[] storepass; // keystore password
    boolean protectedPath; // protected authentication path
    String storetype; // keystore type
    String providerName; // provider name
    List<String> providers = null; // list of provider names
    List<String> providerClasses = null; // list of provider classes
    // arguments for provider constructors
    HashMap<String, String> providerArgs = new HashMap<>();
    char[] keypass; // private key password
    String sigfile; // name of .SF file
    String sigalg; // name of signature algorithm
    String digestalg; // name of digest algorithm
    String signedjar; // output filename
    String tsaUrl; // location of the Timestamping Authority
    String tsaAlias; // alias for the Timestamping Authority's certificate
    String altCertChain; // file to read alternative cert chain from
    String tSAPolicyID;
    String tSADigestAlg;
    boolean verify = false; // verify the jar
    // String verbose = "all"; // verbose output when signing/verifying
    String verbose = null; // verbose output when signing/verifying
    boolean showcerts = false; // show certs when verifying
    boolean debug = false; // debug
    boolean signManifest = true; // "sign" the whole manifest
    boolean externalSF = true; // leave the .SF out of the PKCS7 block
    boolean strict = true;  // treat warnings as error
    // If there is a time stamp block inside the PKCS7 block file
    boolean hasTimestampBlock = false;
    PKIXBuilderParameters pkixParameters;
    Set<X509Certificate> trustedCerts = new HashSet<>();
    Hashtable<Certificate, String> storeHash = new Hashtable<>();
    Map<CodeSigner, String> cacheForSignerInfo = new IdentityHashMap<>();


    // Severe warnings.

    // Informational warnings
    private boolean hasExpiringCert = false;
    private boolean hasExpiringTsaCert = false;
    private boolean noTimestamp = true;
    // Expiration date. The value could be null if signed by a trusted cert.
    private Date expireDate = null;
    private Date tsaExpireDate = null;
    private int weakAlg = 0; // 1. digestalg, 2. sigalg, 4. tsadigestalg
    private boolean hasExpiredCert = false;
    private boolean hasExpiredTsaCert = false;
    private boolean notYetValidCert = false;
    private boolean chainNotValidated = false;
    private boolean tsaChainNotValidated = false;
    private boolean notSignedByAlias = false;
    private boolean aliasNotInStore = false;
    private boolean hasUnsignedEntry = false;
    private boolean badKeyUsage = false;
    private boolean badExtendedKeyUsage = false;
    private boolean badNetscapeCertType = false;
    private boolean signerSelfSigned = false;
    private Throwable chainNotValidatedReason = null;
    private Throwable tsaChainNotValidatedReason = null;
    private boolean seeWeak = false;
    private Map<CodeSigner, Integer> cacheForInKS = new IdentityHashMap<>();

    // Attention:
    // This is the entry that get launched by the security tool jarsigner.
    public static void main(String args[]) throws Exception {
        Main js = new Main();
        js.run(args);
    }

    static char[] getPass(String modifier, String arg) {
//        char[] output = KeyStoreUtil.getPassWithModifier(modifier, arg, rb);
//        if (output != null) return output;
//        usage();
        return arg.toCharArray();    // Useless, usage() already exit
    }

    static void usageNoArg() {
        System.out.println(rb.getString("Option.lacks.argument"));
        usage();
    }

    static void usage() {
    }

    static void fullusage() {

    }

    public void run(String args[]) {
        try {
            args = parseArgs(args);

            // Try to load and install the specified providers
            if (providers != null) {
                for (String provName : providers) {
                    try {
                        KeyStoreUtil.loadProviderByName(provName,
                                providerArgs.get(provName));
                        if (debug) {
                            System.out.println("loadProviderByName: " + provName);
                        }
                    } catch (IllegalArgumentException e) {
                        throw new Exception(String.format(rb.getString(
                                "provider.name.not.found"), provName));
                    }
                }
            }

            if (providerClasses != null) {
                ClassLoader cl = ClassLoader.getSystemClassLoader();
                for (String provClass : providerClasses) {
                    try {
                        KeyStoreUtil.loadProviderByClass(provClass,
                                providerArgs.get(provClass), cl);
                        if (debug) {
                            System.out.println("loadProviderByClass: " + provClass);
                        }
                    } catch (ClassCastException cce) {
                        throw new Exception(String.format(rb.getString(
                                "provclass.not.a.provider"), provClass));
                    } catch (IllegalArgumentException e) {
                        throw new Exception(String.format(rb.getString(
                                "provider.class.not.found"), provClass), e.getCause());
                    }
                }
            }

            if (verify) {
                try {
                    loadKeyStore(keystore, false);
                } catch (Exception e) {
                    if ((keystore != null) || (storepass != null)) {
                        System.out.println(rb.getString("jarsigner.error.") +
                                e.getMessage());
                        if (debug) {
                            e.printStackTrace();
                        }
                        System.exit(1);
                    }
                }
                /*              if (debug) {
                    SignatureFileVerifier.setDebug(true);
                    ManifestEntryVerifier.setDebug(true);
                }
                */
                verifyJar(new File(jarfile));
            }
        } catch (Exception e) {
            System.out.println(rb.getString("jarsigner.error.") + e);
            if (debug) {
                e.printStackTrace();
            }
            System.exit(1);
        } finally {
            // zero-out private key password
            if (keypass != null) {
                Arrays.fill(keypass, ' ');
                keypass = null;
            }
            // zero-out keystore password
            if (storepass != null) {
                Arrays.fill(storepass, ' ');
                storepass = null;
            }
        }

        if (strict) {
            int exitCode = 0;
            if (weakAlg != 0 || chainNotValidated || hasExpiredCert
                    || hasExpiredTsaCert || notYetValidCert || signerSelfSigned) {
                exitCode |= 4;
            }
            if (badKeyUsage || badExtendedKeyUsage || badNetscapeCertType) {
                exitCode |= 8;
            }
            if (hasUnsignedEntry) {
                exitCode |= 16;
            }
            if (notSignedByAlias || aliasNotInStore) {
                exitCode |= 32;
            }
            if (tsaChainNotValidated) {
                exitCode |= 64;
            }
            if (exitCode != 0) {
                System.exit(exitCode);
            }
        }
    }

    /*
     * Parse command line arguments.
     */
    String[] parseArgs(String args[]) throws Exception {
        /* parse flags */
        int n = 0;

        if (args.length == 0) fullusage();

        String confFile = null;
        String command = "-sign";
        for (n = 0; n < args.length; n++) {
            if (collator.compare(args[n], "-verify") == 0) {
                command = "-verify";
            } else if (collator.compare(args[n], "-conf") == 0) {
                if (n == args.length - 1) {
                    usageNoArg();
                }
                confFile = args[++n];
            }
        }

        if (confFile != null) {
            args = KeyStoreUtil.expandArgs(
                    "jarsigner", confFile, command, null, args);
        }

        debug = Arrays.stream(args).anyMatch(
                x -> collator.compare(x, "-debug") == 0);

        if (debug) {
            // No need to localize debug output
            System.out.println("Command line args: " +
                    Arrays.toString(args));
        }

        for (n = 0; n < args.length; n++) {

            String flags = args[n];
            String modifier = null;

            if (flags.startsWith("-")) {
                int pos = flags.indexOf(':');
                if (pos > 0) {
                    modifier = flags.substring(pos + 1);
                    flags = flags.substring(0, pos);
                }
            }

            if (!flags.startsWith("-")) {
                if (jarfile == null) {
                    jarfile = flags;
                } else {
                    alias = flags;
                    ckaliases.add(alias);
                }
            } else if (collator.compare(flags, "-conf") == 0) {
                if (++n == args.length) usageNoArg();
            } else if (collator.compare(flags, "-keystore") == 0) {
                if (++n == args.length) usageNoArg();
                keystore = args[n];
            } else if (collator.compare(flags, "-storepass") == 0) {
                if (++n == args.length) usageNoArg();
                storepass = getPass(modifier, args[n]);
            } else if (collator.compare(flags, "-storetype") == 0) {
                if (++n == args.length) usageNoArg();
                storetype = args[n];
            } else if (collator.compare(flags, "-providerName") == 0) {
                if (++n == args.length) usageNoArg();
                providerName = args[n];
            } else if (collator.compare(flags, "-provider") == 0 ||
                    collator.compare(flags, "-providerClass") == 0) {
                if (++n == args.length) usageNoArg();
                if (providerClasses == null) {
                    providerClasses = new ArrayList<>(3);
                }
                providerClasses.add(args[n]);

                if (args.length > (n + 1)) {
                    flags = args[n + 1];
                    if (collator.compare(flags, "-providerArg") == 0) {
                        if (args.length == (n + 2)) usageNoArg();
                        providerArgs.put(args[n], args[n + 2]);
                        n += 2;
                    }
                }
            } else if (collator.compare(flags, "-addprovider") == 0) {
                if (++n == args.length) usageNoArg();
                if (providers == null) {
                    providers = new ArrayList<>(3);
                }
                providers.add(args[n]);

                if (args.length > (n + 1)) {
                    flags = args[n + 1];
                    if (collator.compare(flags, "-providerArg") == 0) {
                        if (args.length == (n + 2)) usageNoArg();
                        providerArgs.put(args[n], args[n + 2]);
                        n += 2;
                    }
                }
            } else if (collator.compare(flags, "-protected") == 0) {
                protectedPath = true;
            } else if (collator.compare(flags, "-certchain") == 0) {
                if (++n == args.length) usageNoArg();
                altCertChain = args[n];
            } else if (collator.compare(flags, "-tsapolicyid") == 0) {
                if (++n == args.length) usageNoArg();
                tSAPolicyID = args[n];
            } else if (collator.compare(flags, "-tsadigestalg") == 0) {
                if (++n == args.length) usageNoArg();
                tSADigestAlg = args[n];
            } else if (collator.compare(flags, "-debug") == 0) {
                // Already processed
            } else if (collator.compare(flags, "-keypass") == 0) {
                if (++n == args.length) usageNoArg();
                keypass = getPass(modifier, args[n]);
            } else if (collator.compare(flags, "-sigfile") == 0) {
                if (++n == args.length) usageNoArg();
                sigfile = args[n];
            } else if (collator.compare(flags, "-signedjar") == 0) {
                if (++n == args.length) usageNoArg();
                signedjar = args[n];
            } else if (collator.compare(flags, "-tsa") == 0) {
                if (++n == args.length) usageNoArg();
                tsaUrl = args[n];
            } else if (collator.compare(flags, "-tsacert") == 0) {
                if (++n == args.length) usageNoArg();
                tsaAlias = args[n];
            } else if (collator.compare(flags, "-sectionsonly") == 0) {
                signManifest = false;
            } else if (collator.compare(flags, "-internalsf") == 0) {
                externalSF = false;
            } else if (collator.compare(flags, "-verify") == 0) {
                verify = true;
            } else if (collator.compare(flags, "-verbose") == 0) {
                verbose = (modifier != null) ? modifier : "all";
            } else if (collator.compare(flags, "-sigalg") == 0) {
                if (++n == args.length) usageNoArg();
                sigalg = args[n];
            } else if (collator.compare(flags, "-digestalg") == 0) {
                if (++n == args.length) usageNoArg();
                digestalg = args[n];
            } else if (collator.compare(flags, "-certs") == 0) {
                showcerts = true;
            } else if (collator.compare(flags, "-strict") == 0) {
                strict = true;
            } else if (collator.compare(flags, "-?") == 0 ||
                    collator.compare(flags, "-h") == 0 ||
                    collator.compare(flags, "--help") == 0 ||
                    // -help: legacy.
                    collator.compare(flags, "-help") == 0) {
                fullusage();
            } else {
                System.err.println(
                        rb.getString("Illegal.option.") + flags);
                usage();
            }
        }

        // -certs must always be specified with -verbose
        if (verbose == null) showcerts = false;

        if (jarfile == null) {
            System.err.println(rb.getString("Please.specify.jarfile.name"));
            usage();
        }
        if (!verify && alias == null) {
            System.err.println(rb.getString("Please.specify.alias.name"));
            usage();
        }
        if (!verify && ckaliases.size() > 1) {
            System.err.println(rb.getString("Only.one.alias.can.be.specified"));
            usage();
        }

        if (storetype == null) {
            storetype = KeyStore.getDefaultType();
        }
        storetype = KeyStoreUtil.niceStoreTypeName(storetype);

        try {
            if (signedjar != null && new File(signedjar).getCanonicalPath().equals(
                    new File(jarfile).getCanonicalPath())) {
                signedjar = null;
            }
        } catch (IOException ioe) {
            // File system error?
            // Just ignore it.
        }

        if (P11KEYSTORE.equalsIgnoreCase(storetype) ||
                KeyStoreUtil.isWindowsKeyStore(storetype)) {
            token = true;
            if (keystore == null) {
                keystore = NONE;
            }
        }

        if (NONE.equals(keystore)) {
            nullStream = true;
        }

        if (token && !nullStream) {
            System.err.println(MessageFormat.format(rb.getString
                    (".keystore.must.be.NONE.if.storetype.is.{0}"), storetype));
            usage();
        }

        if (token && keypass != null) {
            System.err.println(MessageFormat.format(rb.getString
                    (".keypass.can.not.be.specified.if.storetype.is.{0}"), storetype));
            usage();
        }

        if (protectedPath) {
            if (storepass != null || keypass != null) {
                System.err.println(rb.getString
                        ("If.protected.is.specified.then.storepass.and.keypass.must.not.be.specified"));
                usage();
            }
        }
        if (KeyStoreUtil.isWindowsKeyStore(storetype)) {
            if (storepass != null || keypass != null) {
                System.err.println(rb.getString
                        ("If.keystore.is.not.password.protected.then.storepass.and.keypass.must.not.be.specified"));
                usage();
            }
        }
        return args;
    }


    public void init(KeystoreProperties keystoreProperties) {
        storetype = KeyStore.getDefaultType();
        storetype = KeyStoreUtil.niceStoreTypeName(storetype);
        ckaliases.add(keystoreProperties.getAlias());
        keystore = keystoreProperties.getPath();
        storepass = keystoreProperties.getPassword().toCharArray();
        try {
            loadKeyStore(keystore, false);
        } catch (Exception e) {
            if ((keystore != null) || (storepass != null)) {
                logger.error(rb.getString("jarsigner.error.") +
                        e.getMessage());
            }
        }
    }

    public VerifyResult verifyJar(File jarName) {
        final VerifyResult verifyResult = new VerifyResult();

        boolean anySigned = false;  // if there exists entry inside jar signed

        Map<String, String> digestMap = new HashMap<>();
        Map<String, PKCS7> sigMap = new HashMap<>();
        Map<String, String> sigNameMap = new HashMap<>();
        Map<String, String> unparsableSignatures = new HashMap<>();
        try (JarFile jf = new JarFile(jarName, true)) {
            Vector<JarEntry> entriesVec = new Vector<>();
            byte[] buffer = new byte[8192];

            Enumeration<JarEntry> entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry je = entries.nextElement();
                entriesVec.addElement(je);
                try (InputStream is = jf.getInputStream(je)) {
                    String name = je.getName();
                    if (signatureRelated(name)
                            && SignatureFileVerifier.isBlockOrSF(name)) {
                        String alias = name.substring(name.lastIndexOf('/') + 1,
                                name.lastIndexOf('.'));
                        try {
                            if (name.endsWith(".SF")) {
                                Manifest sf = new Manifest(is);
                                boolean found = false;
                                for (Object obj : sf.getMainAttributes().keySet()) {
                                    String key = obj.toString();
                                    if (key.endsWith("-Digest-Manifest")) {
                                        digestMap.put(alias,
                                                key.substring(0, key.length() - 16));
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    unparsableSignatures.putIfAbsent(alias,
                                            String.format(
                                                    rb.getString("history.unparsable"),
                                                    name));
                                }
                            } else {
                                sigNameMap.put(alias, name);
                                sigMap.put(alias, new PKCS7(is));
                            }
                        } catch (IOException ioe) {
                            unparsableSignatures.putIfAbsent(alias, String.format(
                                    rb.getString("history.unparsable"), name));
                        }
                    } else {
                        while (is.read(buffer, 0, buffer.length) != -1) {
                            // we just read. this will throw a SecurityException
                            // if  a signature/digest check fails.
                        }
                    }
                }
            }

            Manifest man = jf.getManifest();
            boolean hasSignature = false;

            // The map to record display info, only used when -verbose provided
            //      key: signer info string
            //      value: the list of files with common key
            Map<String, List<String>> output = new LinkedHashMap<>();

            if (man != null) {
                if (verbose != null) System.out.println();
                Enumeration<JarEntry> e = entriesVec.elements();

                String tab = "\t";

                while (e.hasMoreElements()) {
                    JarEntry je = e.nextElement();
                    String name = je.getName();

                    hasSignature = hasSignature
                            || SignatureFileVerifier.isBlockOrSF(name);

                    CodeSigner[] signers = je.getCodeSigners();
                    boolean isSigned = (signers != null);
                    anySigned |= isSigned;
                    hasUnsignedEntry |= !je.isDirectory() && !isSigned
                            && !signatureRelated(name);

                    int inStoreWithAlias = inKeyStore(signers);

                    boolean inStore = (inStoreWithAlias & IN_KEYSTORE) != 0;

                    notSignedByAlias |= (inStoreWithAlias & NOT_ALIAS) != 0;
                    if (keystore != null) {
                        aliasNotInStore |= isSigned && !inStore;
                    }

                    // Only used when -verbose provided
                    StringBuilder sb = new StringBuilder();
                    if (verbose != null) {
                        boolean inManifest =
                                ((man.getAttributes(name) != null) ||
                                        (man.getAttributes("./" + name) != null) ||
                                        (man.getAttributes("/" + name) != null));
                        sb.append(isSigned ? rb.getString("s") : SPACE)
                                .append(inManifest ? rb.getString("m") : SPACE)
                                .append(inStore ? rb.getString("k") : SPACE)
                                .append((inStoreWithAlias & NOT_ALIAS) != 0 ? 'X' : ' ')
                                .append(SPACE);
                        sb.append('|');
                    }

                    // When -certs provided, display info has extra empty
                    // lines at the beginning and end.
                    if (isSigned) {
                        if (showcerts) sb.append('\n');
                        for (CodeSigner signer : signers) {
                            // signerInfo() must be called even if -verbose
                            // not provided. The method updates various
                            // warning flags.
                            String si = signerInfo(signer, tab);
                            if (showcerts) {
                                sb.append(si);
                                sb.append('\n');
                            }
                        }
                    } else if (showcerts && !Objects.equals(verbose, "all")) {
                        // Print no info for unsigned entries when -verbose:all,
                        // to be consistent with old behavior.
                        if (signatureRelated(name)) {
                            sb.append('\n')
                                    .append(tab)
                                    .append(rb
                                            .getString(".Signature.related.entries."))
                                    .append("\n\n");
                        } else {
                            sb.append('\n').append(tab)
                                    .append(rb.getString(".Unsigned.entries."))
                                    .append("\n\n");
                        }
                    }

                    if (verbose != null) {
                        String label = sb.toString();
                        if (signatureRelated(name)) {
                            // Entries inside META-INF and other unsigned
                            // entries are grouped separately.
                            label = "-" + label;
                        }

                        // The label finally contains 2 parts separated by '|':
                        // The legend displayed before the entry names, and
                        // the cert info (if -certs specified).

                        if (!output.containsKey(label)) {
                            output.put(label, new ArrayList<>());
                        }

                        StringBuilder fb = new StringBuilder();
                        String s = Long.toString(je.getSize());
                        for (int i = 6 - s.length(); i > 0; --i) {
                            fb.append(' ');
                        }
                        fb.append(s).append(' ').
                                append(new Date(je.getTime()).toString());
                        fb.append(' ').append(name);

                        output.get(label).add(fb.toString());
                    }
                }
            }
            if (verbose != null) {
                for (Entry<String, List<String>> s : output.entrySet()) {
                    List<String> files = s.getValue();
                    String key = s.getKey();
                    if (key.charAt(0) == '-') { // the signature-related group
                        key = key.substring(1);
                    }
                    int pipe = key.indexOf('|');
                    if (verbose.equals("all")) {
                        for (String f : files) {
                            System.out.println(key.substring(0, pipe) + f);
                            System.out.printf(key.substring(pipe + 1));
                        }
                    } else {
                        if (verbose.equals("grouped")) {
                            for (String f : files) {
                                System.out.println(key.substring(0, pipe) + f);
                            }
                        } else if (verbose.equals("summary")) {
                            System.out.print(key.substring(0, pipe));
                            if (files.size() > 1) {
                                System.out.println(files.get(0) + " " +
                                        String.format(rb.getString(
                                                ".and.d.more."), files.size() - 1));
                            } else {
                                System.out.println(files.get(0));
                            }
                        }
                        System.out.printf(key.substring(pipe + 1));
                    }
                }
                System.out.println();
                System.out.println(rb.getString(
                        ".s.signature.was.verified."));
                System.out.println(rb.getString(
                        ".m.entry.is.listed.in.manifest"));
                System.out.println(rb.getString(
                        ".k.at.least.one.certificate.was.found.in.keystore"));
                if (ckaliases.size() > 0) {
                    System.out.println(rb.getString(
                            ".X.not.signed.by.specified.alias.es."));
                }
            }
            if (man == null) {
                System.out.println(rb.getString("no.manifest."));
            }

            // If signer is a trusted cert or private entry in user's own
            // keystore, it can be self-signed. Please note aliasNotInStore
            // is always false when ~/.keystore is used.
            if (!aliasNotInStore && keystore != null) {
                signerSelfSigned = false;
            }

            // Even if the verbose option is not specified, all out strings
            // must be generated so seeWeak can be updated.
            if (!digestMap.isEmpty()
                    || !sigMap.isEmpty()
                    || !unparsableSignatures.isEmpty()) {
                if (verbose != null) {
                    System.out.println();
                }
                for (String s : sigMap.keySet()) {
                    if (!digestMap.containsKey(s)) {
                        unparsableSignatures.putIfAbsent(s, String.format(
                                rb.getString("history.nosf"), s));
                    }
                }
                for (String s : digestMap.keySet()) {
                    PKCS7 p7 = sigMap.get(s);
                    if (p7 != null) {
                        String history;
                        try {
                            SignerInfo si = p7.getSignerInfos()[0];
                            X509Certificate signer = si.getCertificate(p7);
                            String digestAlg = digestMap.get(s);
                            String sigAlg = AlgorithmId.makeSigAlg(
                                    si.getDigestAlgorithmId().getName(),
                                    si.getDigestEncryptionAlgorithmId().getName());
                            PublicKey key = signer.getPublicKey();
                            PKCS7 tsToken = si.getTsToken();
                            if (tsToken != null) {
                                hasTimestampBlock = true;
                                SignerInfo tsSi = tsToken.getSignerInfos()[0];
                                X509Certificate tsSigner = tsSi.getCertificate(tsToken);
                                byte[] encTsTokenInfo = tsToken.getContentInfo().getData();
                                TimestampToken tsTokenInfo = new TimestampToken(encTsTokenInfo);
                                PublicKey tsKey = tsSigner.getPublicKey();
                                String tsDigestAlg = tsTokenInfo.getHashAlgorithm().getName();
                                String tsSigAlg = AlgorithmId.makeSigAlg(
                                        tsSi.getDigestAlgorithmId().getName(),
                                        tsSi.getDigestEncryptionAlgorithmId().getName());
                                Calendar c = Calendar.getInstance(
                                        TimeZone.getTimeZone("UTC"),
                                        Locale.getDefault(Locale.Category.FORMAT));
                                c.setTime(tsTokenInfo.getDate());
                                history = String.format(
                                        rb.getString("history.with.ts"),
                                        signer.getSubjectX500Principal(),
                                        withWeak(digestAlg, DIGEST_PRIMITIVE_SET),
                                        withWeak(sigAlg, SIG_PRIMITIVE_SET),
                                        withWeak(key),
                                        c,
                                        tsSigner.getSubjectX500Principal(),
                                        withWeak(tsDigestAlg, DIGEST_PRIMITIVE_SET),
                                        withWeak(tsSigAlg, SIG_PRIMITIVE_SET),
                                        withWeak(tsKey));
                            } else {
                                history = String.format(
                                        rb.getString("history.without.ts"),
                                        signer.getSubjectX500Principal(),
                                        withWeak(digestAlg, DIGEST_PRIMITIVE_SET),
                                        withWeak(sigAlg, SIG_PRIMITIVE_SET),
                                        withWeak(key));
                            }
                        } catch (Exception e) {
                            // The only usage of sigNameMap, remember the name
                            // of the block file if it's invalid.
                            history = String.format(
                                    rb.getString("history.unparsable"),
                                    sigNameMap.get(s));
                        }
                        if (verbose != null) {
                            System.out.println(history);
                        }
                    } else {
                        unparsableSignatures.putIfAbsent(s, String.format(
                                rb.getString("history.nobk"), s));
                    }
                }
                if (verbose != null) {
                    for (String s : unparsableSignatures.keySet()) {
                        System.out.println(unparsableSignatures.get(s));
                    }
                }
            }
            // System.out.println();
            if (!anySigned) {
                if (seeWeak) {
                    if (verbose != null) {
                        verifyResult.getErrors().add(rb.getString("jar.treated.unsigned.see.weak.verbose"));
                        System.out.println("\n  " +
                                DisabledAlgorithmConstraints.PROPERTY_JAR_DISABLED_ALGS +
                                "=" + Security.getProperty(DisabledAlgorithmConstraints.PROPERTY_JAR_DISABLED_ALGS));
                    } else {
                        verifyResult.getErrors().add(rb.getString("jar.treated.unsigned.see.weak"));
                    }
                } else if (hasSignature) {
                    verifyResult.getErrors().add(rb.getString("jar.treated.unsigned"));
                } else {
                    verifyResult.getErrors().add(rb.getString("jar.is.unsigned"));
                }
            } else {
                displayMessagesAndResult(verifyResult, false);
            }
            return verifyResult;
        } catch (Exception e) {
            verifyResult.getErrors().add(rb.getString("jarsigner.") + e);
            logger.error("Failed to verify jar", e);
        } // close the resource

        return null;
    }

    private void displayMessagesAndResult(VerifyResult verifyResult, boolean isSigning) {
        String result;
        List<String> errors = verifyResult.getErrors();
        List<String> warnings = verifyResult.getWarnings();
        List<String> info = verifyResult.getInfo();

        boolean signerNotExpired = expireDate == null
                || expireDate.after(new Date());

        if (badKeyUsage || badExtendedKeyUsage || badNetscapeCertType ||
                notYetValidCert || chainNotValidated || hasExpiredCert ||
                hasUnsignedEntry || signerSelfSigned || (weakAlg != 0) ||
                aliasNotInStore || notSignedByAlias ||
                tsaChainNotValidated ||
                (hasExpiredTsaCert && !signerNotExpired)) {

            if (strict) {
                result = rb.getString(isSigning
                        ? "jar.signed.with.signer.errors."
                        : "jar.verified.with.signer.errors.");
            } else {
                result = rb.getString(isSigning
                        ? "jar.signed."
                        : "jar.verified.");
            }

            if (badKeyUsage) {
                errors.add(rb.getString(isSigning
                        ? "The.signer.certificate.s.KeyUsage.extension.doesn.t.allow.code.signing."
                        : "This.jar.contains.entries.whose.signer.certificate.s.KeyUsage.extension.doesn.t.allow.code.signing."));
            }

            if (badExtendedKeyUsage) {
                errors.add(rb.getString(isSigning
                        ? "The.signer.certificate.s.ExtendedKeyUsage.extension.doesn.t.allow.code.signing."
                        : "This.jar.contains.entries.whose.signer.certificate.s.ExtendedKeyUsage.extension.doesn.t.allow.code.signing."));
            }

            if (badNetscapeCertType) {
                errors.add(rb.getString(isSigning
                        ? "The.signer.certificate.s.NetscapeCertType.extension.doesn.t.allow.code.signing."
                        : "This.jar.contains.entries.whose.signer.certificate.s.NetscapeCertType.extension.doesn.t.allow.code.signing."));
            }

            // only in verifying
            if (hasUnsignedEntry) {
                errors.add(rb.getString(
                        "This.jar.contains.unsigned.entries.which.have.not.been.integrity.checked."));
            }
            if (hasExpiredCert) {
                errors.add(rb.getString(isSigning
                        ? "The.signer.certificate.has.expired."
                        : "This.jar.contains.entries.whose.signer.certificate.has.expired."));
            }
            if (notYetValidCert) {
                errors.add(rb.getString(isSigning
                        ? "The.signer.certificate.is.not.yet.valid."
                        : "This.jar.contains.entries.whose.signer.certificate.is.not.yet.valid."));
            }

            if (chainNotValidated) {
                errors.add(String.format(rb.getString(isSigning
                                ? "The.signer.s.certificate.chain.is.invalid.reason.1"
                                : "This.jar.contains.entries.whose.certificate.chain.is.invalid.reason.1"),
                        chainNotValidatedReason.getLocalizedMessage()));
            }

            if (hasExpiredTsaCert) {
                errors.add(rb.getString("The.timestamp.has.expired."));
            }
            if (tsaChainNotValidated) {
                errors.add(String.format(rb.getString(isSigning
                                ? "The.tsa.certificate.chain.is.invalid.reason.1"
                                : "This.jar.contains.entries.whose.tsa.certificate.chain.is.invalid.reason.1"),
                        tsaChainNotValidatedReason.getLocalizedMessage()));
            }

            // only in verifying
            if (notSignedByAlias) {
                errors.add(
                        rb.getString("This.jar.contains.signed.entries.which.is.not.signed.by.the.specified.alias.es."));
            }

            // only in verifying
            if (aliasNotInStore) {
                errors.add(rb.getString("This.jar.contains.signed.entries.that.s.not.signed.by.alias.in.this.keystore."));
            }

            if (signerSelfSigned) {
                errors.add(rb.getString(isSigning
                        ? "The.signer.s.certificate.is.self.signed."
                        : "This.jar.contains.entries.whose.signer.certificate.is.self.signed."));
            }

            // weakAlg only detected in signing. The jar file is
            // now simply treated unsigned in verifying.
            if ((weakAlg & 1) == 1) {
                errors.add(String.format(
                        rb.getString("The.1.algorithm.specified.for.the.2.option.is.considered.a.security.risk."),
                        digestalg, "-digestalg"));
            }

            if ((weakAlg & 2) == 2) {
                errors.add(String.format(
                        rb.getString("The.1.algorithm.specified.for.the.2.option.is.considered.a.security.risk."),
                        sigalg, "-sigalg"));
            }
            if ((weakAlg & 4) == 4) {
                errors.add(String.format(
                        rb.getString("The.1.algorithm.specified.for.the.2.option.is.considered.a.security.risk."),
                        tSADigestAlg, "-tsadigestalg"));
            }
            if ((weakAlg & 8) == 8) {
                errors.add(String.format(
                        rb.getString("The.1.signing.key.has.a.keysize.of.2.which.is.considered.a.security.risk."),
                        privateKey.getAlgorithm(), KeyUtil.getKeySize(privateKey)));
            }
        } else {
            result = rb.getString(isSigning ? "jar.signed." : "jar.verified.");
        }

        if (hasExpiredTsaCert) {
            // No need to warn about expiring if already expired
            hasExpiringTsaCert = false;
        }

        if (hasExpiringCert ||
                (hasExpiringTsaCert && expireDate != null) ||
                (noTimestamp && expireDate != null) ||
                (hasExpiredTsaCert && signerNotExpired)) {

            if (hasExpiredTsaCert && signerNotExpired) {
                if (expireDate != null) {
                    warnings.add(String.format(
                            rb.getString("The.timestamp.expired.1.but.usable.2"),
                            tsaExpireDate,
                            expireDate));
                }
                // Reset the flag so exit code is 0
                hasExpiredTsaCert = false;
            }
            if (hasExpiringCert) {
                warnings.add(rb.getString(isSigning
                        ? "The.signer.certificate.will.expire.within.six.months."
                        : "This.jar.contains.entries.whose.signer.certificate.will.expire.within.six.months."));
            }
            if (hasExpiringTsaCert && expireDate != null) {
                if (expireDate.after(tsaExpireDate)) {
                    warnings.add(String.format(rb.getString(
                            "The.timestamp.will.expire.within.one.year.on.1.but.2"), tsaExpireDate, expireDate));
                } else {
                    warnings.add(String.format(rb.getString(
                            "The.timestamp.will.expire.within.one.year.on.1"), tsaExpireDate));
                }
            }
            if (noTimestamp && expireDate != null) {
                if (hasTimestampBlock) {
                    warnings.add(String.format(rb.getString(isSigning
                            ? "invalid.timestamp.signing"
                            : "bad.timestamp.verifying"), expireDate));
                } else {
                    warnings.add(String.format(rb.getString(isSigning
                            ? "no.timestamp.signing"
                            : "no.timestamp.verifying"), expireDate));
                }
            }
        }

        if (verbose != null) {
            logger.info(result);
        }
//        if (strict) {
//            if (!errors.isEmpty() && verbose != null) {
//                System.out.println();
//                System.out.println(rb.getString("Error."));
//                errors.forEach(System.out::println);
//            }
//            if (!warnings.isEmpty() && verbose != null) {
//                System.out.println();
//                System.out.println(rb.getString("Warning."));
//                warnings.forEach(System.out::println);
//            }
//        } else {
//            if (!errors.isEmpty() || !warnings.isEmpty()) {
//                System.out.println();
//                System.out.println(rb.getString("Warning."));
//                errors.forEach(System.out::println);
//                warnings.forEach(System.out::println);
//            }
//        }
//        if (!isSigning && (!errors.isEmpty() || !warnings.isEmpty())) {
//            if (!(verbose != null && showcerts)) {
//                System.out.println();
//                System.out.println(rb.getString(
//                        "Re.run.with.the.verbose.and.certs.options.for.more.details."));
//            }
//        }

        if (isSigning || verbose != null) {
            // Always print out expireDate, unless expired or expiring.
            if (!hasExpiringCert && !hasExpiredCert
                    && expireDate != null && signerNotExpired) {
                info.add(String.format(rb.getString(
                        "The.signer.certificate.will.expire.on.1."), expireDate));
            }
            if (!noTimestamp) {
                if (!hasExpiringTsaCert && !hasExpiredTsaCert && tsaExpireDate != null) {
                    if (signerNotExpired) {
                        info.add(String.format(rb.getString(
                                "The.timestamp.will.expire.on.1."), tsaExpireDate));
                    } else {
                        info.add(String.format(rb.getString(
                                "signer.cert.expired.1.but.timestamp.good.2."),
                                expireDate,
                                tsaExpireDate));
                    }
                }
            }
        }

//        if (!info.isEmpty() && verbose != null) {
//            System.out.println();
//            info.forEach(System.out::println);
//        }
    }

    private String withWeak(String alg, Set<CryptoPrimitive> primitiveSet) {
        if (DISABLED_CHECK.permits(primitiveSet, alg, null)) {
            return alg;
        } else {
            seeWeak = true;
            return String.format(rb.getString("with.weak"), alg);
        }
    }

    private String withWeak(PublicKey key) {
        if (DISABLED_CHECK.permits(SIG_PRIMITIVE_SET, key)) {
            int kLen = KeyUtil.getKeySize(key);
            if (kLen >= 0) {
                return String.format(rb.getString("key.bit"), kLen);
            } else {
                return rb.getString("unknown.size");
            }
        } else {
            seeWeak = true;
            return String.format(
                    rb.getString("key.bit.weak"), KeyUtil.getKeySize(key));
        }
    }

    /**
     * Returns a string about a certificate:
     * <p>
     * [<tab>] <cert-type> [", " <subject-DN>] [" (" <keystore-entry-alias> ")"]
     * [<validity-period> | <expiry-warning>]
     * [<key-usage-warning>]
     * <p>
     * Note: no newline character at the end.
     * <p>
     * This method sets global flags like hasExpiringCert, hasExpiredCert,
     * notYetValidCert, badKeyUsage, badExtendedKeyUsage, badNetscapeCertType,
     * hasExpiringTsaCert, hasExpiredTsaCert.
     *
     * @param isTsCert   true if c is in the TSA cert chain, false otherwise.
     * @param checkUsage true to check code signer keyUsage
     */
    String printCert(boolean isTsCert, String tab, Certificate c,
                     Date timestamp, boolean checkUsage) throws Exception {

        StringBuilder certStr = new StringBuilder();
        String space = rb.getString("SPACE");
        X509Certificate x509Cert = null;

        if (c instanceof X509Certificate) {
            x509Cert = (X509Certificate) c;
            certStr.append(tab).append(x509Cert.getType())
                    .append(rb.getString("COMMA"))
                    .append(x509Cert.getSubjectDN().getName());
        } else {
            certStr.append(tab).append(c.getType());
        }

        String alias = storeHash.get(c);
        if (alias != null) {
            certStr.append(space).append(alias);
        }

        if (x509Cert != null) {

            certStr.append("\n").append(tab).append("[");

            if (trustedCerts.contains(x509Cert)) {
                certStr.append(rb.getString("trusted.certificate"));
            } else {
                Date notAfter = x509Cert.getNotAfter();
                try {
                    boolean printValidity = true;
                    if (isTsCert) {
                        if (tsaExpireDate == null || tsaExpireDate.after(notAfter)) {
                            tsaExpireDate = notAfter;
                        }
                    } else {
                        if (expireDate == null || expireDate.after(notAfter)) {
                            expireDate = notAfter;
                        }
                    }
                    if (timestamp == null) {
                        x509Cert.checkValidity();
                        // test if cert will expire within six months (or one year for tsa)
                        long age = isTsCert ? ONE_YEAR : SIX_MONTHS;
                        if (notAfter.getTime() < System.currentTimeMillis() + age) {
                            if (isTsCert) {
                                hasExpiringTsaCert = true;
                            } else {
                                hasExpiringCert = true;
                            }
                            if (expiringTimeForm == null) {
                                expiringTimeForm = new MessageFormat(
                                        rb.getString("certificate.will.expire.on"));
                            }
                            Object[] source = {notAfter};
                            certStr.append(expiringTimeForm.format(source));
                            printValidity = false;
                        }
                    } else {
                        x509Cert.checkValidity(timestamp);
                    }
                    if (printValidity) {
                        if (validityTimeForm == null) {
                            validityTimeForm = new MessageFormat(
                                    rb.getString("certificate.is.valid.from"));
                        }
                        Object[] source = {x509Cert.getNotBefore(), notAfter};
                        certStr.append(validityTimeForm.format(source));
                    }
                } catch (CertificateExpiredException cee) {
                    if (isTsCert) {
                        hasExpiredTsaCert = true;
                    } else {
                        hasExpiredCert = true;
                    }

                    if (expiredTimeForm == null) {
                        expiredTimeForm = new MessageFormat(
                                rb.getString("certificate.expired.on"));
                    }
                    Object[] source = {notAfter};
                    certStr.append(expiredTimeForm.format(source));

                } catch (CertificateNotYetValidException cnyve) {
                    if (!isTsCert) notYetValidCert = true;

                    if (notYetTimeForm == null) {
                        notYetTimeForm = new MessageFormat(
                                rb.getString("certificate.is.not.valid.until"));
                    }
                    Object[] source = {x509Cert.getNotBefore()};
                    certStr.append(notYetTimeForm.format(source));
                }
            }
            certStr.append("]");

            if (checkUsage) {
                boolean[] bad = new boolean[3];
                checkCertUsage(x509Cert, bad);
                if (bad[0] || bad[1] || bad[2]) {
                    String x = "";
                    if (bad[0]) {
                        x = "KeyUsage";
                    }
                    if (bad[1]) {
                        if (x.length() > 0) x = x + ", ";
                        x = x + "ExtendedKeyUsage";
                    }
                    if (bad[2]) {
                        if (x.length() > 0) x = x + ", ";
                        x = x + "NetscapeCertType";
                    }
                    certStr.append("\n").append(tab)
                            .append(MessageFormat.format(rb.getString(
                                    ".{0}.extension.does.not.support.code.signing."), x));
                }
            }
        }
        return certStr.toString();
    }

    private String printTimestamp(String tab, Timestamp timestamp) {

        if (signTimeForm == null) {
            signTimeForm =
                    new MessageFormat(rb.getString("entry.was.signed.on"));
        }
        Object[] source = {timestamp.getTimestamp()};

        return tab + "[" +
                signTimeForm.format(source) + "]";
    }

    private int inKeyStoreForOneSigner(CodeSigner signer) {
        if (cacheForInKS.containsKey(signer)) {
            return cacheForInKS.get(signer);
        }

        int result = 0;
        List<? extends Certificate> certs = signer.getSignerCertPath().getCertificates();
        for (Certificate c : certs) {
            String alias = storeHash.get(c);
            if (alias != null) {
                if (alias.startsWith("(")) {
                    result |= IN_KEYSTORE;
                }
                if (ckaliases.contains(alias.substring(1, alias.length() - 1))) {
                    result |= SIGNED_BY_ALIAS;
                }
            } else {
                if (store != null) {
                    try {
                        alias = store.getCertificateAlias(c);
                    } catch (KeyStoreException kse) {
                        // never happens, because keystore has been loaded
                    }
                    if (alias != null) {
                        storeHash.put(c, "(" + alias + ")");
                        result |= IN_KEYSTORE;
                    }
                }
                if (ckaliases.contains(alias)) {
                    result |= SIGNED_BY_ALIAS;
                }
            }
        }
        cacheForInKS.put(signer, result);
        return result;
    }

    int inKeyStore(CodeSigner[] signers) {

        if (signers == null)
            return 0;

        int output = 0;

        for (CodeSigner signer : signers) {
            int result = inKeyStoreForOneSigner(signer);
            output |= result;
        }
        if (ckaliases.size() > 0 && (output & SIGNED_BY_ALIAS) == 0) {
            output |= NOT_ALIAS;
        }
        return output;
    }

    /**
     * signature-related files include:
     * . META-INF/MANIFEST.MF
     * . META-INF/SIG-*
     * . META-INF/*.SF
     * . META-INF/*.DSA
     * . META-INF/*.RSA
     * . META-INF/*.EC
     */
    private boolean signatureRelated(String name) {
        return SignatureFileVerifier.isSigningRelated(name);
    }

    /**
     * Returns a string of signer info, with a newline at the end.
     * Called by verifyJar().
     */
    private String signerInfo(CodeSigner signer, String tab) throws Exception {
        if (cacheForSignerInfo.containsKey(signer)) {
            return cacheForSignerInfo.get(signer);
        }
        List<? extends Certificate> certs = signer.getSignerCertPath().getCertificates();
        // signing time is only displayed on verification
        Timestamp ts = signer.getTimestamp();
        String tsLine = "";
        if (ts != null) {
            tsLine = printTimestamp(tab, ts) + "\n";
        }
        // Spaces before the ">>> Signer" and other lines are the same.

        String result = certsAndTSInfo(tab, tab, certs, ts);
        cacheForSignerInfo.put(signer, tsLine + result);
        return result;
    }

    /**
     * Fills info on certs and timestamp into a StringBuilder, sets
     * warning flags (through printCert) and validates cert chains.
     *
     * @param tab1  spaces before the ">>> Signer" line
     * @param tab2  spaces before the other lines
     * @param certs the signer cert
     * @param ts    the timestamp, can be null
     * @return the info as a string
     */
    private String certsAndTSInfo(
            String tab1,
            String tab2,
            List<? extends Certificate> certs, Timestamp ts)
            throws Exception {

        Date timestamp;
        if (ts != null) {
            timestamp = ts.getTimestamp();
            noTimestamp = false;
        } else {
            timestamp = null;
        }
        // display the certificate(sb). The first one is end-entity cert and
        // its KeyUsage should be checked.
        boolean first = true;
        StringBuilder sb = new StringBuilder();
        sb.append(tab1).append(rb.getString("...Signer")).append('\n');
        for (Certificate c : certs) {
            sb.append(printCert(false, tab2, c, timestamp, first));
            sb.append('\n');
            first = false;
        }
        try {
            validateCertChain(Validator.VAR_CODE_SIGNING, certs, ts);
        } catch (Exception e) {
            chainNotValidated = true;
            chainNotValidatedReason = e;
            sb.append(tab2).append(rb.getString(".Invalid.certificate.chain."))
                    .append(e.getLocalizedMessage()).append("]\n");
        }
        if (ts != null) {
            sb.append(tab1).append(rb.getString("...TSA")).append('\n');
            for (Certificate c : ts.getSignerCertPath().getCertificates()) {
                sb.append(printCert(true, tab2, c, null, false));
                sb.append('\n');
            }
            try {
                validateCertChain(Validator.VAR_TSA_SERVER,
                        ts.getSignerCertPath().getCertificates(), null);
            } catch (Exception e) {
                tsaChainNotValidated = true;
                tsaChainNotValidatedReason = e;
                sb.append(tab2).append(rb.getString(".Invalid.TSA.certificate.chain."))
                        .append(e.getLocalizedMessage()).append("]\n");
            }
        }
        if (certs.size() == 1
                && KeyStoreUtil.isSelfSigned((X509Certificate) certs.get(0))) {
            signerSelfSigned = true;
        }

        return sb.toString();
    }

    void loadKeyStore(String keyStoreName, boolean prompt) {

        if (!nullStream && keyStoreName == null) {
            keyStoreName = System.getProperty("user.home") + File.separator
                    + ".keystore";
        }

        try {
            try {
                KeyStore caks = KeyStoreUtil.getCacertsKeyStore();
                if (caks != null) {
                    Enumeration<String> aliases = caks.aliases();
                    while (aliases.hasMoreElements()) {
                        String a = aliases.nextElement();
                        try {
                            trustedCerts.add((X509Certificate) caks.getCertificate(a));
                        } catch (Exception e2) {
                            // ignore, when a SecretkeyEntry does not include a cert
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore, if cacerts cannot be loaded
            }

            if (providerName == null) {
                store = KeyStore.getInstance(storetype);
            } else {
                store = KeyStore.getInstance(storetype, providerName);
            }

            // Get pass phrase
            // XXX need to disable echo; on UNIX, call getpass(char *prompt)Z
            // and on NT call ??
            if (token && storepass == null && !protectedPath
                    && !KeyStoreUtil.isWindowsKeyStore(storetype)) {
                storepass = getPass
                        (rb.getString("Enter.Passphrase.for.keystore."));
            } else if (!token && storepass == null && prompt) {
                storepass = getPass
                        (rb.getString("Enter.Passphrase.for.keystore."));
            }

            try {
                if (nullStream) {
                    store.load(null, storepass);
                } else {
                    keyStoreName = keyStoreName.replace(File.separatorChar, '/');
                    URL url = null;
                    try {
                        url = new URL(keyStoreName);
                    } catch (java.net.MalformedURLException e) {
                        // try as file
                        url = new File(keyStoreName).toURI().toURL();
                    }
                    InputStream is = null;
                    try {
                        is = url.openStream();
                        store.load(is, storepass);
                    } finally {
                        if (is != null) {
                            is.close();
                        }
                    }
                }
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    String a = aliases.nextElement();
                    try {
                        X509Certificate c = (X509Certificate) store.getCertificate(a);
                        // Only add TrustedCertificateEntry and self-signed
                        // PrivateKeyEntry
                        if (store.isCertificateEntry(a) ||
                                c.getSubjectDN().equals(c.getIssuerDN())) {
                            trustedCerts.add(c);
                        }
                    } catch (Exception e2) {
                        // ignore, when a SecretkeyEntry does not include a cert
                    }
                }
            } finally {
                try {
                    pkixParameters = new PKIXBuilderParameters(
                            trustedCerts.stream()
                                    .map(c -> new TrustAnchor(c, null))
                                    .collect(Collectors.toSet()),
                            null);
                    pkixParameters.setRevocationEnabled(false);
                } catch (InvalidAlgorithmParameterException ex) {
                    // Only if tas is empty
                }
            }
        } catch (IOException | NoSuchProviderException | NoSuchAlgorithmException ioe) {
            throw new RuntimeException(rb.getString("keystore.load.") +
                    ioe.getMessage());
        } catch (java.security.cert.CertificateException ce) {
            throw new RuntimeException(rb.getString("certificate.exception.") +
                    ce.getMessage());
        } catch (KeyStoreException kse) {
            throw new RuntimeException
                    (rb.getString("unable.to.instantiate.keystore.class.") +
                            kse.getMessage());
        }
    }

    /**
     * Check if userCert is designed to be a code signer
     *
     * @param userCert the certificate to be examined
     * @param bad      3 booleans to show if the KeyUsage, ExtendedKeyUsage,
     *                 NetscapeCertType has codeSigning flag turned on.
     *                 If null, the class field badKeyUsage, badExtendedKeyUsage,
     *                 badNetscapeCertType will be set.
     */
    void checkCertUsage(X509Certificate userCert, boolean[] bad) {

        // Can act as a signer?
        // 1. if KeyUsage, then [0:digitalSignature] or
        //    [1:nonRepudiation] should be true
        // 2. if ExtendedKeyUsage, then should contains ANY or CODE_SIGNING
        // 3. if NetscapeCertType, then should contains OBJECT_SIGNING
        // 1,2,3 must be true

        if (bad != null) {
            bad[0] = bad[1] = bad[2] = false;
        }

        boolean[] keyUsage = userCert.getKeyUsage();
        if (keyUsage != null) {
            keyUsage = Arrays.copyOf(keyUsage, 9);
            if (!keyUsage[0] && !keyUsage[1]) {
                if (bad != null) {
                    bad[0] = true;
                    badKeyUsage = true;
                }
            }
        }

        try {
            List<String> xKeyUsage = userCert.getExtendedKeyUsage();
            if (xKeyUsage != null) {
                if (!xKeyUsage.contains("2.5.29.37.0") // anyExtendedKeyUsage
                        && !xKeyUsage.contains("1.3.6.1.5.5.7.3.3")) {  // codeSigning
                    if (bad != null) {
                        bad[1] = true;
                        badExtendedKeyUsage = true;
                    }
                }
            }
        } catch (java.security.cert.CertificateParsingException e) {
            // shouldn't happen
        }

        try {
            // OID_NETSCAPE_CERT_TYPE
            byte[] netscapeEx = userCert.getExtensionValue
                    ("2.16.840.1.113730.1.1");
            if (netscapeEx != null) {
                DerInputStream in = new DerInputStream(netscapeEx);
                byte[] encoded = in.getOctetString();
                encoded = new DerValue(encoded).getUnalignedBitString()
                        .toByteArray();

                NetscapeCertTypeExtension extn =
                        new NetscapeCertTypeExtension(encoded);

                Boolean val = extn.get(NetscapeCertTypeExtension.OBJECT_SIGNING);
                if (!val) {
                    if (bad != null) {
                        bad[2] = true;
                        badNetscapeCertType = true;
                    }
                }
            }
        } catch (IOException e) {
            //
        }
    }

    void error(String message) {
        System.out.println(rb.getString("jarsigner.") + message);
        System.exit(1);
    }


    /**
     * Validates a cert chain.
     *
     * @param parameter this might be a timestamp
     */
    void validateCertChain(String variant, List<? extends Certificate> certs,
                           Timestamp parameter)
            throws Exception {
        try {
            Validator.getInstance(Validator.TYPE_PKIX,
                    variant,
                    pkixParameters)
                    .validate(certs.toArray(new X509Certificate[certs.size()]),
                            null, parameter);
        } catch (Exception e) {
            if (debug) {
                e.printStackTrace();
            }

            // Exception might be dismissed if another warning flag
            // is already set by printCert.

            if (variant.equals(Validator.VAR_TSA_SERVER) &&
                    e instanceof ValidatorException) {
                // Throw cause if it's CertPathValidatorException,
                if (e.getCause() != null &&
                        e.getCause() instanceof CertPathValidatorException) {
                    e = (Exception) e.getCause();
                    Throwable t = e.getCause();
                    if ((t instanceof CertificateExpiredException &&
                            hasExpiredTsaCert)) {
                        // we already have hasExpiredTsaCert
                        return;
                    }
                }
            }

            if (variant.equals(Validator.VAR_CODE_SIGNING) &&
                    e instanceof ValidatorException) {
                // Throw cause if it's CertPathValidatorException,
                if (e.getCause() != null &&
                        e.getCause() instanceof CertPathValidatorException) {
                    e = (Exception) e.getCause();
                    Throwable t = e.getCause();
                    if ((t instanceof CertificateExpiredException &&
                            hasExpiredCert) ||
                            (t instanceof CertificateNotYetValidException &&
                                    notYetValidCert)) {
                        // we already have hasExpiredCert and notYetValidCert
                        return;
                    }
                }
                if (e instanceof ValidatorException) {
                    ValidatorException ve = (ValidatorException) e;
                    if (ve.getErrorType() == ValidatorException.T_EE_EXTENSIONS &&
                            (badKeyUsage || badExtendedKeyUsage || badNetscapeCertType)) {
                        // We already have badKeyUsage, badExtendedKeyUsage
                        // and badNetscapeCertType
                        return;
                    }
                }
            }
            throw e;
        }
    }

    char[] getPass(String prompt) {
        System.err.print(prompt);
        System.err.flush();
        try {
            char[] pass = Password.readPassword(System.in);

            if (pass == null) {
                error(rb.getString("you.must.enter.key.password"));
            } else {
                return pass;
            }
        } catch (IOException ioe) {
            error(rb.getString("unable.to.read.password.") + ioe.getMessage());
        }
        // this shouldn't happen
        return null;
    }
}
