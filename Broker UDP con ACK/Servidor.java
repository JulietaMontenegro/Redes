import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Arrays;
import java.util.HashSet;

public class Servidor {
    private DatagramSocket datagramSocket;
    private HashSet<Topico>listaTopicos;
    private byte[] buffer= new byte[256];

    public Servidor(DatagramSocket datagramSocket) {
        this.datagramSocket = datagramSocket;
        this.listaTopicos= new HashSet<Topico>();
    }
    public void recibirReenviar(){
        while(true){
            try{
                DatagramPacket datagramPacket= new DatagramPacket(buffer, buffer.length);
                datagramSocket.receive(datagramPacket);
                InetAddress direccion=datagramPacket.getAddress();
                int port= datagramPacket.getPort();
                String mensaje= new String(datagramPacket.getData(), 0, datagramPacket.getLength());

                if(mensaje.contains("/s")){
                    boolean existe=false;
                    for(Topico topico: listaTopicos){
                        if(topico.getNombre().equals(String.valueOf(mensaje.charAt(mensaje.length()-1)))){
                            topico.suscribir(direccion, port);
                            existe=true;
                        }
                    }
                    if(existe==false){
                        Topico nuevo= new Topico(String.valueOf(mensaje.charAt(mensaje.length()-1)));
                        nuevo.suscribir(direccion, port);
                        listaTopicos.add(nuevo);
                    }
                }else if(mensaje.contains("/d")){
                    for(Topico topico: listaTopicos){
                        if(topico.getNombre().equals(String.valueOf(mensaje.charAt(mensaje.length()-1)))){
                            topico.desuscribir(direccion, port);
                        }
                    }
                }
                String lista="";
                for(Topico topico: listaTopicos){
                    lista= lista + " TOPICO " + topico.getNombre() + " CANT " + topico.getListaSuscriptores().size();
                }
                System.out.println(lista);

                System.out.println("Mensaje que llegó de un cliente: " + mensaje);
                datagramPacket= new DatagramPacket(buffer, buffer.length, direccion, port);
                datagramSocket.send(datagramPacket);

                if(!mensaje.contains("/s") && !mensaje.contains("/d") ) {
                    for (Topico topico : listaTopicos) {
                        if (topico.getNombre().equals(String.valueOf(mensaje.charAt(0)))) {
                            for (Socket socket : topico.getListaSuscriptores()) {
                                datagramPacket = new DatagramPacket(buffer, buffer.length, socket.getInetAddress(), socket.getPuerto());
                                datagramSocket.send(datagramPacket);
                                System.out.println("Se mandó msjs a topicos");
                            }
                        }
                    }
                }
                Arrays.fill(buffer, (byte) 0);
            } catch (IOException e) {
                e.printStackTrace();
                break;
            }
        }
    }

    public static void main(String[] args) throws SocketException {
        DatagramSocket datagramSocket= new DatagramSocket(5000);
        Servidor servidor= new Servidor(datagramSocket);
        servidor.recibirReenviar();

    }
}