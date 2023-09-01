import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

public class Servidor {
    private DatagramSocket datagramSocket;
    private HashSet<Topico>listaTopicos;
    private java.security.PrivateKey PrivateKey = null;
    private java.security.PublicKey PublicKey = null;
    private HashMap<String, Socket> listaClavesPublicas;

    private byte[] buffer= new byte[256];

    public Servidor(DatagramSocket datagramSocket) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        this.datagramSocket = datagramSocket;
        this.listaTopicos= new HashSet<Topico>();
        genKeyPair(1024);
    }
    public void genKeyPair(int size) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        KeyPair kp = kpg.genKeyPair();

        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        this.PrivateKey = privateKey;
        this.PublicKey = publicKey;
    }
    public java.security.PrivateKey getPrivateKey() {
        return PrivateKey;
    }
    public void setPrivateKey(java.security.PrivateKey privateKey) {
        PrivateKey = privateKey;
    }
    public java.security.PublicKey getPublicKey() {
        return PublicKey;
    }
    public void setPublicKey(java.security.PublicKey publicKey) {
        PublicKey = publicKey;
    }
    public String getPrivateKeyString(){
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(this.PrivateKey.getEncoded());
        return bytesToString(pkcs8EncodedKeySpec.getEncoded());
    }
    public String getPublicKeyString(){
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(this.PublicKey.getEncoded());
        return bytesToString(x509EncodedKeySpec.getEncoded());
    }
    public String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
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
                }else if(mensaje.charAt(0) == '&' && mensaje.charAt(1) == 'c' && mensaje.charAt(2) == '&'){
                    System.out.println("Recibi una clave");
                    mensaje=mensaje.substring(3);
                    listaClavesPublicas.put(mensaje, new Socket(direccion, port));
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

    public static void main(String[] args) throws SocketException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        DatagramSocket datagramSocket= new DatagramSocket(5000);
        Servidor servidor= new Servidor(datagramSocket);
        servidor.recibirReenviar();

    }
}