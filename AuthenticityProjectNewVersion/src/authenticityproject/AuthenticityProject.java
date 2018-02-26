/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package authenticityproject;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.security.cert.CertificateEncodingException;

import pt.gov.cartaodecidadao.PTEID_EIDCard;
import pt.gov.cartaodecidadao.PTEID_Exception;
import pt.gov.cartaodecidadao.PTEID_Sod;
import pteidlib.PteidException;
import pteidlib.pteid;

/**
 *
 * @author João Saraiva - FEITO COM A NOVA VERSÃO DO MIDDLEWARE DO GOVERNO
 */
public class AuthenticityProject {

    private static PTEID_EIDCard card;
    public static PTEID_Sod sod; //SOD object

    /*
     * Carrega a biblioteca "pteidlibj"
     * @throws UnsatisfiedLinkError caso ocorra erro do middleware
     */
    static {
        try {
            System.loadLibrary("pteidlibj");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
    }

    public static void main(String[] args) throws PTEID_Exception, IOException, CertificateException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateEncodingException {

        try {

            pteid.Init("");
            pteid.SetSODChecking(false);

            //SOD File
            AuxFile aux = new AuxFile(card);
            byte[] bytesSod = aux.getSODbytes(sod);
            aux.createSODFile(bytesSod, "sodFile.ber");

            //Certificates
            X509Certificate[] certs = aux.getCardCertificates();
            aux.writeX509CertsToFile(certs);

        } catch (PteidException ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());

        }

    }
}
