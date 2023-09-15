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
import java.util.Base64;


public class Cliente  {
    private DatagramSocket datagramSocket;
    private InetAddress inetAddress;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey publicKeyServer;
    private byte[] buffer= new byte[2048];

    public Cliente(DatagramSocket datagramSocket, InetAddress inetAddress) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        this.datagramSocket = datagramSocket;
        this.inetAddress = inetAddress;
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
    //convierte la publicKey en string con formato PEM
    public static String publicKeyToPEM(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        StringBuilder pemKey = new StringBuilder();
        pemKey.append("-----BEGIN PUBLIC KEY-----\n");
        pemKey.append(base64PublicKey);
        pemKey.append("\n-----END PUBLIC KEY-----");
        return pemKey.toString();
    }
    //convierto de formato string PEM a publicKey
    public static PublicKey convertPEMToRSA(String pemPublicKey) throws Exception {
        // Elimina caracteristicas propias de formato PEM
        String pemData = pemPublicKey.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(pemData);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }
    //mandar la clave publica al servidor
    public void mandarClavePublica() throws Exception {
        String claveString= publicKeyToPEM(this.publicKey);
        System.out.println(publicKeyToPEM(this.publicKey));
        buffer=claveString.getBytes();
        DatagramPacket datagramPacket= new DatagramPacket(buffer, buffer.length, inetAddress, 5000);
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
    public byte[] stringToBytes(String s) {
        byte[] b2 = new BigInteger(s, 36).toByteArray();
        return Arrays.copyOfRange(b2, 1, b2.length);
    }
    public String Encrypt(String msj) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException,IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException, NoSuchProviderException {
        byte[] encryptedBytes;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKeyServer);
        encryptedBytes = cipher.doFinal(msj.getBytes());

        return bytesToString(encryptedBytes);
    }
    public String EncryptHash(String msj) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException,IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException, NoSuchProviderException {
        byte[] encryptedBytes;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
        encryptedBytes = cipher.doFinal(msj.getBytes());

        return bytesToString(encryptedBytes);
    }
    public String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
    }

    public void setPublicKeyServer(PublicKey publicKeyServer) {
        this.publicKeyServer = publicKeyServer;
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

    public void mandarRecibir() throws Exception {
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
                        if(this.publicKeyServer==null){
                            setPublicKeyServer(convertPEMToRSA(recibido));
                            System.out.println("server:" +convertPEMToRSA(recibido) );
                        }else{
                            System.out.println("Llega " + recibido);
                            System.out.println(Decrypt(recibido));
                        }
                        Arrays.fill(buffer, (byte) 0);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                } catch (IllegalBlockSizeException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (BadPaddingException e) {
                    throw new RuntimeException(e);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            recibir.start();
            while (true) {
                Arrays.fill(buffer, (byte) 0);
                String mensaje = entrada.nextLine();
                String hash= hashear(mensaje);
                System.out.println("EL HASH " + hash);
                hash= EncryptHash(hash);
                System.out.println("ENCRIPTADO " + hash);
                mensaje= Encrypt(mensaje);
                String msjFinal= mensaje + "°" + hash;
                System.out.println(msjFinal);
                buffer = msjFinal.getBytes();
                DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length, inetAddress, 5000); // 5000 es el numero de puerto del servidor
                datagramSocket.send(datagramPacket);
                Arrays.fill(buffer, (byte) 0);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) throws Exception {
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