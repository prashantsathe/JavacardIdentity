import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class JCClient {

  public static void main(String[] args) {
    try {
      Socket sock = new Socket("localhost", 8080);
      if (!sock.getKeepAlive()) {
        sock.setKeepAlive(true);
      }
      if (sock.isConnected()) {
        OutputStream os = sock.getOutputStream();
        InputStream is = sock.getInputStream();
        for (int i = 0; i < 1; i++) {
          System.out.println("Client connected to server localhost");

          // os.write(Utils.hexStringToByteArray("801E4000007F"));
          // os.write(Utils.hexStringToByteArray("801040002281A41A10000002011A300000031908001A500000C81A000100011A200000014204057F"));
          os.write(Utils.hexStringToByteArray(
              "801140002283A21A2000000441011A200000064140035000000000000000000000000000000000007F"));
          // os.write(Utils.hexStringToByteArray("801140003E83A61A700001F7011A1000000218201A3000000318801A200000014200011A2000000441011A2000000641400350000000000000000000000000000000007F"));

          os.flush();
          // InputStream is = sock.getInputStream();
          byte[] inBytes = new byte[261];
          is.read(inBytes);

          System.out
              .println("Response from server " + Utils.byteArrayToHexString(inBytes) + " length: " + inBytes.length);
        }
      }
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

}
