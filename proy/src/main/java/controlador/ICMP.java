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
import org.pcap4j.packet.AbstractPacket.AbstractBuilder;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
public class ICMP {

    private static final String READ_TIMEOUT_KEY
    = ICMP.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY
    = ICMP.class.getName() + ".snaplen";
  private static final int SNAPLEN
    = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
  
   private static final String MTU_KEY
    = ICMP.class.getName() + ".mtu";
  private static final int MTU
    = Integer.getInteger(MTU_KEY, 1403); // [bytes]


  public static boolean EnviarICMP(String ip_origen,String ip_destino, int numBytes, PcapNetworkInterface dispositivo) throws PcapNativeException, NotOpenException, UnknownHostException
  {
    

    PcapNetworkInterface nif = dispositivo;
   

    PcapHandle manejadorIcmp
      = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle enviarManejador
      = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();


    //MAC de la IP de origen
    MacAddress mac_origen;
    List<PcapAddress> lista = nif.getAddresses();
      String ip_esteCompu = lista.get(1).getAddress().getHostAddress();
    if(ip_esteCompu.equals(ip_origen))
    {
         List<LinkLayerAddress> lista_MAC = nif.getLinkLayerAddresses();
        
       mac_origen = MacAddress.getByAddress(lista_MAC.get(0).getAddress());
    }else
    {
     
     mac_origen = MacAddress.getByAddress(ARP.EnviarARP(ip_origen, dispositivo));
    }
     
     
     //MAC destino
     MacAddress mac_destino;
     mac_destino = MacAddress.getByAddress(ARP.EnviarARP(ip_destino, dispositivo));
    
    try {
      manejadorIcmp.setFilter(
        "icmp and ether dst " + Pcaps.toBpfString(mac_origen),
        BpfProgram.BpfCompileMode.OPTIMIZE
      );

      PacketListener escucha
        = new PacketListener() 
        {
            public void gotPacket(Packet packet) {
            }
        };

      Task t = new Task(manejadorIcmp, escucha);
      pool.execute(t);

       /*int random = 0;
      //Generar caracteres aleatorios
      char[] carac = new char[] {'A','C','D', 'E','F','G','H', 'I','J','K','L', 'M','N','O','P', 'Q','R','S','T', 'U','V','W','X', 'Y','Z','B'};
      char ran;
      byte[] datos = new byte[numBytes];
      for (int i = 0; i < numBytes; i++) 
      {
          random = (int)Math.random();
          ran = carac[random*26];
        datos[i] = (byte)ran;
      }*/
       
      char[] nombre = {'n','e','l','s','o','n'};
        
      char ran;
      byte[] datos = new byte[numBytes];
      for (int i = 0; i < 6; i++) 
      {

        datos[i] = (byte) nombre[i];
      }
      


      IcmpV4EchoPacket.Builder constructor_echo = new IcmpV4EchoPacket.Builder();
      constructor_echo
        .identifier((short)1)
        .payloadBuilder(new UnknownPacket.Builder().rawData(datos));

      IcmpV4CommonPacket.Builder constructor_icmp = new IcmpV4CommonPacket.Builder();
      constructor_icmp
        .type(IcmpV4Type.ECHO)
        .code(IcmpV4Code.NO_CODE)
        .payloadBuilder(constructor_echo)
        .correctChecksumAtBuild(true);


      IpV4Packet.Builder ipv4_constructor = new IpV4Packet.Builder();
      try {
        ipv4_constructor
          .version(IpVersion.IPV4)
          .tos(IpV4Rfc791Tos.newInstance((byte)0))
          .ttl((byte)100)
          .protocol(IpNumber.ICMPV4)
          .srcAddr((Inet4Address)InetAddress.getByName(ip_origen))
          .dstAddr((Inet4Address)InetAddress.getByName(ip_destino))
          .payloadBuilder(constructor_icmp)
          .correctChecksumAtBuild(true)
          .correctLengthAtBuild(true);
      } catch (UnknownHostException e1) {
        throw new IllegalArgumentException(e1);
      }

      
      
      EthernetPacket.Builder trama_constructor = new EthernetPacket.Builder();
      trama_constructor.dstAddr(MacAddress.getByName(mac_destino.toString(), ":"))
                  .srcAddr(mac_origen)
                  .type(EtherType.IPV4)
                  .paddingAtBuild(true);

      


        for (
          final Packet ipV4Packet: IpV4Helper.fragment(ipv4_constructor.build(), MTU)
        ) {
          trama_constructor.payloadBuilder(
            new AbstractBuilder() {
              @Override
              public Packet build() {
                return ipV4Packet;
              }
            }
          );

          Packet p = trama_constructor.build();
          enviarManejador.sendPacket(p);

          try {
            Thread.sleep(100);
          } catch (InterruptedException e) {
            break;
          }
        }

       
      
      
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      if (manejadorIcmp != null && manejadorIcmp.isOpen()) {
        try {
          manejadorIcmp.breakLoop();
        } catch (NotOpenException noe) {}
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {}
        manejadorIcmp.close();
      }
      if (enviarManejador != null && enviarManejador.isOpen()) {
        enviarManejador.close();
      }
      if (pool != null && !pool.isShutdown()) {
        pool.shutdown();
      }
    }
      return true;
  }

  private static class Task implements Runnable {

    private PcapHandle manejador;
    private PacketListener escucha;

    public Task(PcapHandle handle, PacketListener listener) {
      this.manejador = handle;
      this.escucha = listener;
    }

    public void run() {
      try {
        manejador.loop(-1, escucha);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
      } catch (NotOpenException e) {
        e.printStackTrace();
      }
    }

  }

}