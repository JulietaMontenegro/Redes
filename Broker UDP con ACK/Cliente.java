import java.io.IOException;
import java.net.*;
import java.util.Arrays;
import java.util.Scanner;

public class Cliente  {
    private DatagramSocket datagramSocket;
    private InetAddress inetAddress;
    private byte[] buffer;

    public Cliente(DatagramSocket datagramSocket, InetAddress inetAddress) {
        this.datagramSocket = datagramSocket;
        this.inetAddress = inetAddress;
    }

    public void mandarRecibir() {
        Scanner entrada = new Scanner(System.in);

        try {
            Thread recibir = new Thread(() -> {
                try {
                    while (true) {
                        byte[] buffer2 = new byte[1024];
                        DatagramPacket datagramPacket2 = new DatagramPacket(buffer2, buffer2.length);
                        datagramSocket.receive(datagramPacket2);
                        String recibido = new String(datagramPacket2.getData(), 0, datagramPacket2.getLength());
                        System.out.println(recibido);
                        Arrays.fill(buffer, (byte) 0);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            recibir.start();

            while (true) {
                String mensaje = entrada.nextLine();
                buffer = mensaje.getBytes();
                DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length, inetAddress, 5000); // 5000 es el numero de puerto del servidor
                datagramSocket.send(datagramPacket);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) throws SocketException, UnknownHostException {
        DatagramSocket datagramSocket= new DatagramSocket();
        InetAddress inetAddress= InetAddress.getByName("localhost");
        Cliente c1= new Cliente(datagramSocket, inetAddress);
        System.out.println("Para suscribirse a un tópico mande: /s (nombre tópico) ejemplo: /s F");
        System.out.println("Para mandar un mensaje: (letra del tópico) (escriba el mensaje) ejemplo: A hola");
        System.out.println("Para desuscribirse de un tópico mande: /d (letra del tópico) ejemplo: /d F");
        System.out.println("Al mandar un mensaje por un tópico primero le aparecerá lo que le llegó al sistema y luego el mensaje que usted envió y circula por los tópicos");
        c1.mandarRecibir();
    }
}