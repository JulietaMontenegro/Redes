import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Servidor {
    private DatagramSocket datagramSocket;
    private HashSet<Topico>listaTopicos;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private HashMap<PublicKey, Socket>listaClaves;
    private byte[] buffer= new byte[2048];

    public Servidor(DatagramSocket datagramSocket) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        this.datagramSocket = datagramSocket;
        this.listaTopicos= new HashSet<Topico>();
        this.listaClaves=new HashMap<>();
        genKeyPair(1024);
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    //genero las claves
    public void genKeyPair(int size) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        KeyPair kp = kpg.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    //convierto de formato string PEM a publicKey
    public static PublicKey convertPEMToRSA(String pemPublicKey) throws Exception {
        // Elimina caracteristicas propias de formato PEM
        System.out.println("Hola genero clave");
        String pemData = pemPublicKey.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(pemData);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }
    //encriptar mensajes
    public String Encrypt(String msj, PublicKey publicKeyCliente) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException,IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException, NoSuchProviderException {
        byte[] encryptedBytes;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyCliente);
        encryptedBytes = cipher.doFinal(msj.getBytes());

        return bytesToString(encryptedBytes);
    }
    public String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
    }
    public static String publicKeyToPEM(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        StringBuilder pemKey = new StringBuilder();
        pemKey.append("-----BEGIN PUBLIC KEY-----\n");
        pemKey.append(base64PublicKey);
        pemKey.append("\n-----END PUBLIC KEY-----");
        return pemKey.toString();
    }
    public void mandarClavePublica(InetAddress direccion, int port) throws Exception {
        String claveString= publicKeyToPEM(this.publicKey);
        buffer=claveString.getBytes();
        DatagramPacket datagramPacket= new DatagramPacket(buffer, buffer.length, direccion, port);
        datagramSocket.send(datagramPacket);
        Arrays.fill(buffer, (byte) 0);
    }
    public String Decrypt(String result) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedBytes;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        decryptedBytes = cipher.doFinal(stringToBytes(result));
        return new String(decryptedBytes);
    }
    public String DecryptHash(String result, PublicKey claveActual) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedBytes;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, claveActual);
        decryptedBytes = cipher.doFinal(stringToBytes(result));
        return new String(decryptedBytes);
    }
    public byte[] stringToBytes(String s) {
        byte[] b2 = new BigInteger(s, 36).toByteArray();
        return Arrays.copyOfRange(b2, 1, b2.length);
    }
    public String hashear(String mensaje) throws NoSuchAlgorithmException {
        // get an instance of the SHA-256 message digest algorithm
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // compute the hash of the input string
        byte[] hash = md.digest(mensaje.getBytes());

        // convert the hash to a hexadecimal string
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        // print the hash
        return hexString.toString();
    }

    public void recibirReenviar() throws NoSuchAlgorithmException {
        while(true){
            try{
                DatagramPacket datagramPacket= new DatagramPacket(buffer, buffer.length);
                datagramSocket.receive(datagramPacket);
                InetAddress direccion=datagramPacket.getAddress();
                int port= datagramPacket.getPort();
                String mensaje = new String(datagramPacket.getData(), 0, datagramPacket.getLength());
                PublicKey claveActual=null;
                boolean integridad=false;
                Socket actual=new Socket(direccion,port);
                System.out.println("Llega " + mensaje);

                boolean existeEnLista=false;
                for(Map.Entry<PublicKey, Socket>entrada:listaClaves.entrySet()){
                    if(entrada.getValue().getInetAddress().equals(direccion) && entrada.getValue().getPuerto()==port){
                        existeEnLista=true;
                        break;
                    }
                }
                boolean enviarConfirmacion=true;
                if(!existeEnLista){
                    this.listaClaves.put(convertPEMToRSA(mensaje), actual);
                    enviarConfirmacion=false;
                    mandarClavePublica(direccion,port);
                }else{
                    for(Map.Entry<PublicKey, Socket>entrada:listaClaves.entrySet()){
                        if(entrada.getValue().getInetAddress().equals(direccion) && entrada.getValue().getPuerto()==port){
                            claveActual=entrada.getKey();
                        }
                    }
                    int size=mensaje.length();
                    int delimitador=0;
                    for(int i=0;i<size; i++){
                        if(mensaje.charAt(i) == '°'){
                            delimitador=i;
                            break;
                        }
                    }
                    String hashMsj=mensaje.substring(delimitador + 1);
                    hashMsj= DecryptHash(hashMsj, claveActual);
                    mensaje=mensaje.substring(0, delimitador);
                    mensaje= Decrypt(mensaje);
                    System.out.println("MENSAJEEE " +  mensaje);
                    System.out.println("HAAASH  " + hashMsj);
                    System.out.println(hashear(mensaje));

                    if(hashear(mensaje).equals(hashMsj)){
                        integridad=true;
                    }

                    System.out.println("Mensaje que llegó de un cliente: " + mensaje);
                    if(enviarConfirmacion) {
                        if(integridad){ if(mensaje.contains("/s")){
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
                            mensaje="Sé que vos enviaste " + mensaje;

                        }else{
                            mensaje="Se manipuló la info por terceros, por favor mandá otra vez";
                        }
                        buffer= Encrypt(mensaje, claveActual).getBytes();
                        datagramPacket= new DatagramPacket(buffer, buffer.length, direccion, port);
                        datagramSocket.send(datagramPacket);
                    }else{
                        String msj="Recibí tu clave pública";
                        buffer= Encrypt(msj, claveActual).getBytes();
                        datagramPacket=new DatagramPacket(buffer, buffer.length, direccion, port);
                        datagramSocket.send(datagramPacket);
                    }

                    PublicKey claveSuscriptor=null;
                    if(!mensaje.contains("/s") && !mensaje.contains("/d") ) {
                        if (integridad) {
                            for (Topico topico : listaTopicos) {
                                if (topico.getNombre().equals(String.valueOf(mensaje.charAt(0)))) {
                                    for (Socket socket : topico.getListaSuscriptores()) {
                                        for (Map.Entry<PublicKey, Socket> entrada : listaClaves.entrySet()) {
                                            if (entrada.getValue().getPuerto() == socket.getPuerto() && entrada.getValue().getInetAddress().equals(socket.getInetAddress())) {
                                                claveSuscriptor = entrada.getKey();
                                                break;
                                            }
                                        }
                                        buffer = Encrypt(mensaje, claveSuscriptor).getBytes();
                                        datagramPacket = new DatagramPacket(buffer, buffer.length, socket.getInetAddress(), socket.getPuerto());
                                        datagramSocket.send(datagramPacket);
                                        System.out.println("Se mandó msjs a topicos");
                                    }
                                }
                            }
                        }
                    }
                }
                Arrays.fill(buffer, (byte) 0);
            } catch (IOException e) {
                e.printStackTrace();
                break;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static void main(String[] args) throws SocketException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        DatagramSocket datagramSocket= new DatagramSocket(5000);
        Servidor servidor= new Servidor(datagramSocket);
        servidor.recibirReenviar();

    }
}