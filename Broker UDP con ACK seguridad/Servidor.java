import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
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
    private SecretKeySpec claveSimetrica;
    private HashMap<PublicKey, Socket>listaClaves;

    public Servidor(DatagramSocket datagramSocket) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException {
        this.datagramSocket = datagramSocket;
        this.listaTopicos= new HashSet<Topico>();
        this.listaClaves=new HashMap<>();
        genKeyPair(1024);
        this.claveSimetrica= crearClave();
    }
    private SecretKeySpec crearClave() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String clave= "Esta clave es secreta";
        byte[] claveEncriptacion = clave.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        claveEncriptacion = sha.digest(claveEncriptacion);
        claveEncriptacion = Arrays.copyOf(claveEncriptacion, 16);
        SecretKeySpec secretKey = new SecretKeySpec(claveEncriptacion, "AES");
        return secretKey;
    }
    public String encriptar(String datos) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKey = this.claveSimetrica;
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] datosEncriptar = datos.getBytes("UTF-8");
        byte[] bytesEncriptados = cipher.doFinal(datosEncriptar);
        String encriptado = Base64.getEncoder().encodeToString(bytesEncriptados);
        return encriptado;
    }
    public String desencriptar(String datosEncriptados) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKey = this.claveSimetrica;
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] bytesEncriptados = Base64.getDecoder().decode(datosEncriptados);
        byte[] datosDesencriptados = cipher.doFinal(bytesEncriptados);
        String datos = new String(datosDesencriptados);

        return datos;
    }
    public  String convertSecretKeyToString() throws NoSuchAlgorithmException {
        byte[] rawData = this.claveSimetrica.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(rawData);
        return encodedKey;
    }
    public SecretKeySpec convertStringToSecretKeyto(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKeySpec originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }
    public void mandarClaveSimetrica(InetAddress direccion, int port,PublicKey claveCliente) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        byte[] buffer;
        String claveString= convertSecretKeyToString();
        String claveEncrip=Encrypt(claveString, claveCliente);
        buffer=claveEncrip.getBytes();
        DatagramPacket datagramPacket= new DatagramPacket(buffer, buffer.length, direccion, port);
        datagramSocket.send(datagramPacket);
        Arrays.fill(buffer, (byte) 0);
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
    public SecretKeySpec getClaveSimetrica() {
        return claveSimetrica;
    }
    public void setClaveSimetrica(SecretKeySpec claveSimetrica) {
        this.claveSimetrica = claveSimetrica;
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
        byte[] buffer;
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
        System.out.println(this.claveSimetrica);
        while(true){
            try{
                byte[] buffer= new byte[5000];
                Arrays.fill(buffer, (byte) 0);
                DatagramPacket datagramPacket= new DatagramPacket(buffer, buffer.length);
                datagramSocket.receive(datagramPacket);
                InetAddress direccion=datagramPacket.getAddress();
                int port= datagramPacket.getPort();
                String mensaje = new String(datagramPacket.getData(), 0, datagramPacket.getLength());
                PublicKey claveActual=null;
                boolean integridad=false;
                Socket actual=new Socket(direccion,port);

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
                    mandarClaveSimetrica(direccion, port, convertPEMToRSA(mensaje));
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
                    mensaje= desencriptar(mensaje);
                    //System.out.println("MENSAJE " +  mensaje);
                    //System.out.println("HASH  " + hashMsj);
                    //System.out.println(hashear(mensaje));

                    if(hashear(mensaje).equals(hashMsj)){
                        System.out.println("Mensaje que llegó de un cliente: " + mensaje);
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
                        String mensajeIntegridad="Sé que vos enviaste " + mensaje;
                        buffer= encriptar(mensajeIntegridad).getBytes();
                        datagramPacket= new DatagramPacket(buffer, buffer.length, direccion, port);
                        datagramSocket.send(datagramPacket);

                        PublicKey claveSuscriptor=null;
                        if(!mensaje.contains("/s") && !mensaje.contains("/d") ) {
                                for (Topico topico : listaTopicos) {
                                    if (topico.getNombre().equals(String.valueOf(mensaje.charAt(0)))) {
                                        System.out.println("entro a los topicosss");
                                        for (Socket socket : topico.getListaSuscriptores()) {
                                            for (Map.Entry<PublicKey, Socket> entrada : listaClaves.entrySet()) {
                                                if (entrada.getValue().getPuerto() == socket.getPuerto() && entrada.getValue().getInetAddress().equals(socket.getInetAddress())) {
                                                    claveSuscriptor = entrada.getKey();
                                                    break;
                                                }
                                            }
                                            buffer = encriptar(mensaje).getBytes();
                                            datagramPacket = new DatagramPacket(buffer, buffer.length, socket.getInetAddress(), socket.getPuerto());
                                            datagramSocket.send(datagramPacket);
                                            System.out.println("Se mandó msjs a topicos");
                                        }
                                    }
                                }
                        }
                    }else {
                        mensaje = "Se manipuló la info por terceros, por favor mandá otra vez";
                        buffer = encriptar(mensaje).getBytes();
                        datagramPacket = new DatagramPacket(buffer, buffer.length, direccion, port);
                        datagramSocket.send(datagramPacket);
                    }

                    if(!enviarConfirmacion) {
                        String msj="Recibí tu clave pública";
                        buffer= encriptar(msj).getBytes();
                        datagramPacket=new DatagramPacket(buffer, buffer.length, direccion, port);
                        datagramSocket.send(datagramPacket);
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

    public static void main(String[] args) throws Exception {
        DatagramSocket datagramSocket= new DatagramSocket(5000);
        Servidor servidor= new Servidor(datagramSocket);
        servidor.recibirReenviar();

    }
}