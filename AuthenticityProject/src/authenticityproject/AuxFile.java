/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package authenticityproject;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.util.ASN1Dump;

import pt.gov.cartaodecidadao.PTEID_ByteArray;
import pt.gov.cartaodecidadao.PTEID_Certificate;
import pt.gov.cartaodecidadao.PTEID_Certificates;
import pt.gov.cartaodecidadao.PTEID_EIDCard;
import pt.gov.cartaodecidadao.PTEID_Exception;
import pt.gov.cartaodecidadao.PTEID_Sod;

import sun.security.pkcs.PKCS7;
import sun.security.x509.AlgorithmId;

/**
 *
 * @author João Saraiva - FEITO COM A NOVA VERSÃO DO MIDDLEWARE DO GOVERNO
 */
public class AuxFile {

    private PTEID_EIDCard card; //Card object

    /*
     * Obtenção dos certificados do cartão de cidadão
     */
    public PTEID_Certificates getCerts() throws PTEID_Exception {
        PTEID_Certificates certs = card.getCertificates();
        return certs;
    }

    public X509Certificate toJavaCertificate(PTEID_Certificate certificate) throws CertificateException, PTEID_Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(certificate.getCertData().GetBytes());
        X509Certificate javaCert = (X509Certificate) cf.generateCertificate(is);

        return javaCert;
    }

    public X509Certificate[] getCardCertificates() throws PTEID_Exception, CertificateException {

        PTEID_Certificates certs = getCerts(); //Obter os certificados
        X509Certificate userCert = toJavaCertificate(certs.getCertFromCard(0)); //Converter para objeto x509Certificate
        X509Certificate subCACert = toJavaCertificate(certs.getCertFromCard(3)); //Converter para objeto x509Certificate
        return new X509Certificate[]{userCert, subCACert};
    }

    //Escrita de um certificado X509 para o ficheiro e adicionar à keystore
    public void saveCerts(javax.security.cert.X509Certificate x509) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
        try (FileOutputStream os = new FileOutputStream("x509certs.pem")) {
            os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
            os.write(org.bouncycastle.util.encoders.Base64.encode(x509.getEncoded()));
            //os.write(Base64.encodeBase64(x509.getEncoded(), true));
            os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);

        InputStream bis = new FileInputStream("x509certs.pem");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        while (bis.available() > 0) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
            trustStore.setCertificateEntry("fiddler" + bis.available(), cert);

        }
    }
    public void writeX509CertsToFile(X509Certificate[] certs) {
        for (X509Certificate x509 : certs) {
            saveCerts(x509);
        }

    }
    //--------------------------------------------------------------------------------------------------------------------------------------------------------------------
    /*
     * Obtenção do ficheiro SOD do cartão
     */
    public static byte[] getSODbytes(PTEID_Sod sod) throws PTEID_Exception {
        PTEID_ByteArray byteArray = sod.getData();
        byte[] bytes = byteArray.GetBytes();
        return bytes;
    }

    public static void createSODFile(byte[] bytes, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            int k = 4;
            byte[] newSod = new byte[bytes.length - k];
            System.arraycopy(bytes, k, newSod, 0, bytes.length - k);

            fos.write(newSod);
            PKCS7 p7 = new PKCS7(newSod);
            X509Certificate[] certificates = p7.getCertificates();
            AlgorithmId[] digestAlgorithmIds = p7.getDigestAlgorithmIds();

            //System.out.println("P7 Version: " + p7.getVersion().toString());
            System.out.println("Dump Object\n" + p7.toString());

            //Utilização da bouncy castle para fazer dump do objeto
            ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(newSod));
            ASN1Object obj2 = (ASN1Object) bIn.readObject();
            System.out.println(ASN1Dump.dumpAsString(obj2, true));

            System.out.println("Total de certificados do ficheiro SOD: " + certificates.length);
            System.out.println("certificates[0] subject DN " + certificates[0].getSubjectDN());

            int certLength;
            try {
                certLength = certificates[0].getEncoded().length;
                System.out.println("certificates[0] len " + certLength);

                for (AlgorithmId digestAlgorithmId : digestAlgorithmIds) {
                    System.out.println("Digest Algorithms ids: " + digestAlgorithmId.getName());
                }
            } catch (java.security.cert.CertificateEncodingException ex) {
                Logger.getLogger(AuxFile.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void saveCerts(X509Certificate x509) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
