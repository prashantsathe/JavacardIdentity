import java.io.IOException;

public interface Simulator {
  byte[] STATUS_OK = Utils.hexStringToByteArray("9000");

  void initaliseSimulator() throws Exception;

  void disconnectSimulator() throws Exception;

  public boolean setupKeymasterOnSimulator() throws Exception;

  byte[] executeApdu(byte[] apdu) throws Exception;

  byte[] decodeDataOut();
}
