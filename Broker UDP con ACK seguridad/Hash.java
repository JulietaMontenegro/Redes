import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Hash {
    public static void main(String[] args) throws NoSuchAlgorithmException {
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
    }

}
