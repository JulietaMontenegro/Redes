import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;


public class Cliente  {
    private DatagramSocket datagramSocket;
    private InetAddress inetAddress;
    private PrivateKey PrivateKey = null;
    private PublicKey PublicKey = null;
    private PublicKey publicKeyServidor= null;
    private byte[] buffer;

    public Cliente(DatagramSocket datagramSocket, InetAddress inetAddress) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        this.datagramSocket = datagramSocket;
        this.inetAddress = inetAddress;
        genKeyPair(1024);
    }

    public java.security.PublicKey getPublicKeyServidor() {
        return publicKeyServidor;
    }

    public void setPublicKeyServidor(java.security.PublicKey publicKeyServidor) {
        this.publicKeyServidor = publicKeyServidor;
    }

    public void genKeyPair(int size) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {
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
    public String Encrypt(String plain) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException,IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException, NoSuchProviderException {
        byte[] encryptedBytes;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.PublicKey);
        encryptedBytes = cipher.doFinal(plain.getBytes());

        return bytesToString(encryptedBytes);
    }

    public void mandarRecibir() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        Scanner entrada = new Scanner(System.in);
        mandarClavePublica();
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
    public void mandarClavePublica() throws IOException {
        String clave="&c&" + getPublicKeyString();
        buffer= clave.getBytes();
        DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length, inetAddress, 5000); // 5000 es el numero de puerto del servidor
        datagramSocket.send(datagramPacket);
    }

    public StringBuilder hashear() throws NoSuchAlgorithmException {
            Scanner entrada= new Scanner(System.in);
            String mensaje= entrada.next();

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
            System.out.println(hexString);
            return hexString;
    }


    public static void main(String[] args) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
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