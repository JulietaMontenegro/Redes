import java.net.InetAddress;
import java.util.HashSet;
import java.util.Iterator;

public class Topico {
    private String nombre;
    private HashSet<Socket> listaSuscriptores;
    public Topico(String nombre){
        this.nombre=nombre;
        this.listaSuscriptores=new HashSet<Socket>();
    }

    public HashSet<Socket> getListaSuscriptores() {
        return listaSuscriptores;
    }
    public void setListaSuscriptores(HashSet<Socket> listaSuscriptores) {
        this.listaSuscriptores = listaSuscriptores;
    }
    public String getNombre() {
        return nombre;
    }
    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public synchronized void suscribir(InetAddress direccion, int puerto){
        Socket nuevoSus= new Socket(direccion, puerto);
        this.listaSuscriptores.add(nuevoSus);
    }
    public void desuscribir(InetAddress direccion, int puerto) {
        Iterator<Socket> iterator = listaSuscriptores.iterator();
        while (iterator.hasNext()) {
            Socket socket = iterator.next();
            if (socket.getInetAddress().equals(direccion) && socket.getPuerto() == puerto) {
                iterator.remove();
            }
        }
    }
}
