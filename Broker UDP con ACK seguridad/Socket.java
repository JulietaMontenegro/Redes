import java.net.InetAddress;

public class Socket {
    private int puerto;
    private InetAddress inetAddress;

    public Socket(InetAddress inetAddress, int puerto) {
        this.puerto = puerto;
        this.inetAddress = inetAddress;
    }
    public int getPuerto() {
        return puerto;
    }
    public void setPuerto(int puerto) {
        this.puerto = puerto;
    }
    public InetAddress getInetAddress() {
        return inetAddress;
    }
    public void setInetAddress(InetAddress inetAddress) {
        this.inetAddress = inetAddress;
    }
}