package com.server.avast.verisign.jarsigner;

import com.server.avast.verisign.config.properties.KeystoreProperties;
import com.server.avast.verisign.utils.JarSignerUtils;
import org.junit.Test;

import java.io.File;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * @author Vitasek L.
 */
public class MainTest {

    @Test
    public void verify() {
        for (int i = 0; i < 10; i++) {
            validFile();
        }
//        final Main main = new Main();
//       main.run(new String[]{"-strict", "-verify","c:\\Users\\Vity\\Downloads\\kubectl-versions-2.1.166.jar", "avast-sign", "-keystore", "c:/Program Files/AdoptOpenJDK/jdk-11.0.7.10-hotspot/lib/security/cacerts", "-storePass", "changeit"});
    }

    private void validFile() {
        final long start = System.nanoTime();

        //final VerifyResult verifyResult = main.verifyJar(new File("c:\\Users\\Vity\\Downloads\\hive-beeline-3.0.0.jar"));
        final File jarFile = new File("c:\\Users\\Vity\\Downloads\\kubectl-versions-2.1.166.jar");
        final KeystoreProperties keystoreProperties = new KeystoreProperties("c:/temp/signcert.p12", "", "avast-sign");
        final VerifyResult verifyResult = JarSignerUtils.verify(jarFile, keystoreProperties);
        System.out.println("verifyResult = " + verifyResult);
        final long start2 = System.nanoTime();
        final long milis = TimeUnit.MILLISECONDS.convert(Duration.ofNanos(start2 - start));
        System.out.println("milis = " + milis);
    }
}