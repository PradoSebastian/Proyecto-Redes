/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controlador;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;




/**
 * @author Sebastián Gutierrez, Nelson Jiménez, Sebastián Prado
 */
public class Main 
{
   
    public static void main(String [] args)        
    {
        
        int opcion;
        String ip_origen;
        String ip_destino = null;
        int tam=0;
        //Seleccionador de dispositivo de red
        PcapNetworkInterface nif;
        try
        {
          nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) 
        {
          e.printStackTrace();
          return;
        }
        do{
        System.out.println("Bienvenidos a nuestro sistema de envios de tramas");
        System.out.println("Seleccione el tipo de trama que desea enviar (1 para ARP, 2 para ICMP, 3 para salir");
        Scanner sc = new Scanner(System.in);
        opcion = sc.nextInt();
        if(opcion== 1)
        {
            byte[] mac_destino=null;
            try {
                System.out.println("Escriba una direccion ip (Ej: 100.23.23.4)");
                ip_destino = sc.next();
               mac_destino = ARP.EnviarARP(ip_destino, nif);
            } catch (PcapNativeException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NotOpenException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnknownHostException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
            if(mac_destino !=null)
                System.out.println("Se ha enviado y recibido correctamente la trama ARP de la IP: " + ip_destino + " con la MAC: " + MacAddress.getByAddress(mac_destino).toString());
            
            
        }else
        if(opcion==2)
        {
           System.out.println("Escriba una direccion ip de origen(Ej: 100.23.23.4)");
                ip_origen = sc.next();
                System.out.println("Escriba una direccion ip destino (Ej: 100.23.23.4");
                ip_destino = sc.next();
                System.out.println("Escriba el tamaño en bytes del mensaje (max 1472)");
                tam = sc.nextInt();
            try {
                ICMP.EnviarICMP(ip_origen, ip_destino, tam, nif);
            } catch (PcapNativeException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NotOpenException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnknownHostException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        }else
            if(opcion == 3)
            {
                System.out.println("Hasta luego");
            }
         else
        {
            System.out.println("ERROR");
        
        }
        
   }while(opcion != 3);
   
    }
    
     
}
