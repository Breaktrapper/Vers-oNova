/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package authenticityproject;

import java.io.IOException;

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

    private PTEID_EIDCard card;
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

    public static void main(String[] args) throws PTEID_Exception, IOException {

        try {

            pteid.Init("");
            pteid.SetSODChecking(false);

            //TESTAR A ESCRITA DO FICHEIRO SOD E FICHEIRO DE CERTIFICADOS EM CASA
            AuxFile aux = new AuxFile();
            byte[] bytesSod = aux.getSODbytes(sod);
            aux.createSODFile(bytesSod, "sodFile.ber");

        } catch (PteidException ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());

        }

    }
}
