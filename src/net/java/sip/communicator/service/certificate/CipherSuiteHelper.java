/*
 * Jitsi, the OpenSource Java VoIP and Instant Messaging client.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.sip.communicator.service.certificate;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Helper methods for calculating which cipher suites to use and in which order 
 * given the configuration and current recommendations.
 *
 * @author Markus Kilas
 */
public class CipherSuiteHelper
{
    
    private static final String TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 
            = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
    private static final String TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 
            = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    private static final String TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
    private static final String TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    
    /**
     * Ordered list of preferred cipher suites.
     * 
     * From draft-saintandre-xmpp-tls-02, 2013-10-19, 4.3. Ciphersuites:
     * "XMPP implementations SHOULD prefer ciphersuites that use
     * algorithms with at least 256 bits of security."
     * 
     * The list is currently put together as follows:
     * Priority 1: Ephemeral Diffie-Hellman of 256 bit
     * Priority 2: Ephemeral Diffie-Hellman of 128 bit
     * Priority 2: Suites of 256 bit
     * Priority 3: suites of 128 bit
     */ 
    private static final List<String> PREFFERED_SUITES = Arrays.asList(
            TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA"
    );
    
    /**
     * Compute the ordered list of cipher suites given the input parameters.
     * @param defaultSuiteList Current list of cipher suites
     * @param supportedSuiteList Set of all supported cipher suites
     * @param blacklisted Set of blacklisted cipher suites
     * @param whitelisted Set of whitelisted cipher suites
     * @param ordering The configured priority order
     * @param adjustByRecommendation True if the application should adjust
     * the list and its ordering
     * @return The final list of cipher suites to use
     */
    public static List<String> computeFinalList(
            final List<String> defaultSuiteList, 
            final Set<String> supportedSuiteList, 
            final Set<String> blacklisted, 
            final Set<String> whitelisted, 
            List<String> ordering, 
            final boolean adjustByRecommendation)
    {        
        final List<String> list;
        
        if (adjustByRecommendation)
        {
            list = adjustListByCurrentRecommendation(new LinkedList<String>(
                    defaultSuiteList));
            ordering = adjustOrderingByCurrentRecommendation(ordering);
        }
        else
        {
            list = new LinkedList<String>(defaultSuiteList);
        }
        
        final List<String> result;
            
        if (whitelisted != null)
        {
            for (String good : whitelisted)
            {
                if (supportedSuiteList.contains(good) && !list.contains(good))
                {
                    list.add(good);
                }
            }
        }

        if (blacklisted != null)
        {
            for (String bad : blacklisted)
            {
                list.remove(bad);
            }
        }
        
        if (ordering != null)
        {
            result = new LinkedList<String>();
            for (String item : ordering)
            {
                if (list.remove(item))
                {
                    result.add(item);
                }
            }
            result.addAll(list);
        }
        else
        {
            result = list;
        }

        // Make sure only supported suites are chosen
        Iterator<String> iterator = result.iterator();
        while (iterator.hasNext())
        {
            String chosen = iterator.next();
            if (!supportedSuiteList.contains(chosen))
            {
                iterator.remove();
            }
        }        

        return result;
    }
    
    /**
     * Adjusts the list by the current recommendation.
     * Weak cipher suites are removed.
     * @param list list of cipher suites that should be adjusted
     * @return a new list of cipher suites
     */
    private static List<String> adjustListByCurrentRecommendation(
            List<String> list)
    {
        final List<String> result = new LinkedList<String>(list);
        // draft-saintandre-xmpp-tls-02, 2013-10-19, 4.3. Ciphersuites:
        Iterator<String> iterator = list.iterator();
        while (iterator.hasNext())
        {
            String suite = iterator.next();
            
            // XMPP implementations MUST NOT negotiate the NULL ciphersuites.
            if (suite.contains("NULL") || suite.contains("anon")
                    
            // XMPP implementations MUST NOT negotiate RC4 ciphersuites
                    || suite.contains("RC4")
                    
            // XMPP implementations MUST NOT negotiate ciphersuites that use so-
            // called "export-level" encryption (including algorithms with 40
            // bits or 56 bits of security)."
                    || suite.contains("EXPORT")
                    
            // "XMPP implementations MUST NOT negotiate ciphersuites that use
            // algorithms that offer less than 128 bits of security (even if 
            // they advertise more bits, such as the 168-bit 3DES 
            // ciphersuites)."
                    || suite.contains("3DES"))
            {
                iterator.remove();
            }
        }
        
        // Given the foregoing considerations, implementation of the following
        // ciphersuites is RECOMMENDED:
//        if (!list.contains(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)) {
//            list.add(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
//        }
//        if (!list.contains(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)) {
//            list.add(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
//        }
//        if (!list.contains(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)) {
//            list.add(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
//        }
//        if (!list.contains(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)) {
//            list.add(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
//        }
        
        return result;
    }
    
    /**
     * Adjusts the ordering by current recommendation.
     * Sets the default preferred ordering if no ordering is given.
     * @param ordering the old ordering (may be null or empty as well)
     * @return the preferred ordering if changed otherwise the original
     */
    private static List<String> adjustOrderingByCurrentRecommendation(
            List<String> ordering)
    {
        final List<String> result;
        if (ordering == null || ordering.isEmpty()) {
            result = Collections.unmodifiableList(PREFFERED_SUITES);
        } else {
            result = ordering;
        }
        return result;
    }
}
