/***************************************************************
 *
 * A program to sign the cert using Java
 *
 * Singapore Polytechnic
 *
 ***************************************************************/

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import sun.security.x509.X500Name;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateAlgorithmId;

public class myCertSign {

	// Algorithm to use for signing the certificate
	private static final String SIG_ALG_NAME = "SHA512withRSA";

	// Validity for the certificate, in days
	private static final int VALIDITY = 365;

	public static void main (String[] args) throws Exception {

    // check number of arguments
	if (args.length != 4) {
		System.out.println("Usage: java myCertSign keystore CA name newname\n");
		System.out.println("Parameters:");
		System.out.println("keystore - location of keystore");
		System.out.println("CA - alias of CA");
		System.out.println("name - alias of the cert to be signed");
		System.out.println("newname - alias of the new signed cert\n");
		System.out.println("Examples:");
		System.out.println("java myCertSign \"c:\\sample\\.keystore\" CA student student_signed\n");
		System.out.println("java myCertSign \"c:\\Documents and Settings\\samsonyeow\\.keystore\" CA student student_signed");
		System.exit(1);
    }

    // Declaration of variables to be used
	String keystoreFile = args[0];
	String caAlias = args[1];
	String certToSignAlias = args[2];
	String newAlias = args[3];

	// Get the password and read the keystore
	BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	System.out.print("Keystore password: ");
	char[] password = in.readLine().toCharArray();
	System.out.print("CA (" + caAlias + ") password: ");
	char[] caPassword = in.readLine().toCharArray();
	System.out.print("Cert (" + certToSignAlias + ") password: ");
	char[] certPassword = in.readLine().toCharArray();

	// Read from the keystore
	FileInputStream input = new FileInputStream(keystoreFile);
	KeyStore keyStore = KeyStore.getInstance("PKCS12");
	keyStore.load(input, password);
	input.close();

	// Get the CA's private key for signing
	PrivateKey caPrivateKey = (PrivateKey)keyStore.getKey(caAlias, caPassword);

	// Get the CA's certificate
	java.security.cert.Certificate caCert = keyStore.getCertificate(caAlias);

	// Create an X509CertImpl, to obtain the name of the issuer
	byte[] encoded = caCert.getEncoded();
	X509CertImpl caCertImpl = new X509CertImpl(encoded);
	X509CertInfo caCertInfo = (X509CertInfo)caCertImpl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
	X500Name issuer = (X500Name)caCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateIssuerName.DN_NAME);

	// Get the cert to be signed
	java.security.cert.Certificate cert = keyStore.getCertificate(certToSignAlias);
	PrivateKey privateKey = (PrivateKey)keyStore.getKey(certToSignAlias, certPassword);
	encoded = cert.getEncoded();
	X509CertImpl certImpl = new X509CertImpl(encoded);
	X509CertInfo certInfo = (X509CertInfo)certImpl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

	// Set the validity
	Date firstDate = new Date();
	Date lastDate = new Date(firstDate.getTime() + VALIDITY*24*60*60*1000L);
	CertificateValidity interval = new CertificateValidity(firstDate, lastDate);
	certInfo.set(X509CertInfo.VALIDITY, interval);

	// Create a new serial number
	certInfo.set(X509CertInfo.SERIAL_NUMBER,new CertificateSerialNumber((int)(firstDate.getTime()/1000)));

	// Set the issuer
	certInfo.set(X509CertInfo.ISSUER +"." + CertificateSubjectName.DN_NAME, issuer);
	AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha512WithRSAEncryption_oid);
	certInfo.set(CertificateAlgorithmId.NAME + "." +
	CertificateAlgorithmId.ALGORITHM, algorithm);
	X509CertImpl newCert = new X509CertImpl(certInfo);

	// Now sign the certificate
	newCert.sign(caPrivateKey, SIG_ALG_NAME);
	keyStore.setKeyEntry(newAlias, privateKey, certPassword, new java.security.cert.Certificate[] { newCert } );

	// Once done, store the keystore
	FileOutputStream output = new FileOutputStream(keystoreFile);
	keyStore.store(output, password);
	output.close();

	}
} // end of program
