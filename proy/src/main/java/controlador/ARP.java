package controlador;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class ARP {

  private static final String COUNT_KEY = ARP.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);

  private static final String READ_TIMEOUT_KEY = ARP.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = ARP.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static MacAddress mac_destino;//mac_destino
  private static boolean llego = false;
  


public static byte[] EnviarARP(String ip_destino, PcapNetworkInterface dispositivo) throws PcapNativeException, NotOpenException, UnknownHostException
   {
  
    PcapNetworkInterface nif = dispositivo;

    PcapHandle manejador = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle enviarManejador = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();
    
    try {
      manejador.setFilter(
          "arp and src host "+InetAddress.getByName(ip_destino).getHostAddress(), BpfCompileMode.OPTIMIZE);

      //Escucha cuando el ARP halla llegado para recibir la MAC
      PacketListener escucha =
          new PacketListener() {
            public void gotPacket(Packet packet) {
              if (packet.contains(ArpPacket.class)) {
                ArpPacket arp = packet.get(ArpPacket.class);
                if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                  ARP.mac_destino = arp.getHeader().getSrcHardwareAddr();
                  llego = true;
                }
              }
           
            }
          };

      Task t = new Task(manejador, escucha);
      pool.execute(t);
      //---------------------------------------------------------------------
   byte [] arp_paquete = new byte[60];

	//MAC destino para ethernet
        for (int i=0;i<6;i++)
        arp_paquete[i] = (byte) 0xFF;

        //MAC origen para Ethernet
        List<LinkLayerAddress> lista_MAC = nif.getLinkLayerAddresses();
        
        byte[] mac_origen = lista_MAC.get(0).getAddress();
        
	for(int i=0; i<mac_origen.length;i++)
	arp_paquete[i+6] = mac_origen[i];
	
	//Type 0X806 segun la IANA para el tipo ARP
	short tipo_short = (short) 0x806;
        byte[] tipo =new byte[] {(byte)(tipo_short>>>8),(byte)(tipo_short&0xFF)};
	arp_paquete[12] = tipo[0];
	arp_paquete[13] = tipo[1];

	//*****Datos ARP*****

	//Espacio MAC
	  short esp_mac_short = (short) 1;
         byte[] esp_mac = new byte[] {(byte)(esp_mac_short>>>8),(byte)(esp_mac_short&0xFF)};
	 arp_paquete[14] = esp_mac[0];
	 arp_paquete[15] = esp_mac[1];

	// Espacio IP
	  short esp_ip_short = (short) 2048;
	  byte[] esp_ip = new byte[] {(byte)(esp_ip_short>>>8),(byte)(esp_ip_short&0xFF)};
	 arp_paquete[16] = esp_ip[0];
	 arp_paquete[17] = esp_ip[1];
	
	//Longitud de las MAC
	arp_paquete[18] = (byte) 6;

	//Longitud de las IP
	arp_paquete[19] = (byte) 4;

	//opcode de Request
	short opcode_s = (byte) 1;
	byte[] opcode = new byte[] {(byte)(opcode_s>>>8),(byte)(opcode_s&0xFF)};
	arp_paquete[20] = opcode[0];
	arp_paquete[21] = opcode[1];

	//MAC origen para ARP 
        for(int i=0; i<mac_origen.length;i++)
	arp_paquete[i+22] = mac_origen[i];
        

	//Direccion ip origen
	List<PcapAddress> lista = nif.getAddresses();
        byte[] ip_origen = lista.get(1).getAddress().getAddress();
	for(int i=0 ; i<4;i++)
	arp_paquete[i+28] = ip_origen[i];

	/*//MAC destino para ARP
         for (int i=0;i<6;i++)
        arp_paquete[i+32] = (byte) 0;*/
    
        String ca = "CA.";
        String fe = "FE.";
        byte[] febyte = fe.getBytes();
     byte[] cabyte=   ca.getBytes();
        for (int i = 32; i < 38; i=i+2) 
        {
            
        arp_paquete[i] = (byte) 0xCA;
        arp_paquete[i+1] = (byte) 0XFE;
            
            
        }

	//Direccion ip destino

	byte[] ip_des = InetAddress.getByName(ip_destino).getAddress();
	for (int i=0;i<ip_des.length;i++)
        arp_paquete[i+38] = ip_des[i];
 
	//Relleno
	for (int i=42;i<60;i++)
        arp_paquete[i] = (byte) 0;
        //---------------------------------------------------------------------

      for (int i = 0; i < COUNT; i++) {
        
        
        enviarManejador.sendPacket(arp_paquete);
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          break;
        }
      }
    } finally {
      if (manejador != null && manejador.isOpen()) {
        manejador.close();
      }
      if (enviarManejador != null && enviarManejador.isOpen()) {
        enviarManejador.close();
      }
      if (pool != null && !pool.isShutdown()) {
        pool.shutdown();
      }


    }
    if(llego)
      return mac_destino.getAddress();
    else
        return null;
  }

  private static class Task implements Runnable {

    private PcapHandle manejador;
    private PacketListener escucha;

    //constructor Task
    public Task(PcapHandle handle, PacketListener listener) {
      this.manejador = handle;
      this.escucha = listener;
    }

    public void run() {
      try {
        manejador.loop(COUNT, escucha);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
        e.printStackTrace();
      } catch (NotOpenException e) {
        e.printStackTrace();
      }
    }
  }
}