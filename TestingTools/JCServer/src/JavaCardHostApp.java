import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;

import com.sun.javacard.apduio.*;

public class JavaCardHostApp {
  private Socket mSock;
  private CadClientInterface mCadClient;
  private Apdu mApdu;
  private OutputStream mOutputStream;
  private InputStream mInputStream;

  public JavaCardHostApp() {
    mApdu = new Apdu();
  }

  public void establishConnectionToSimulator() throws IOException {

    mSock = new Socket("localhost", 9025);
    System.out.println("Able to connect to socket");
    mOutputStream = mSock.getOutputStream();
    mInputStream = mSock.getInputStream();

    mCadClient = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, mInputStream, mOutputStream);

  }

  public void closeConnection() throws IOException {
    mSock.close();

  }

  public void powerUp() throws IOException, CadTransportException {

    System.out.println("Sending powerUp signal");
    mCadClient.powerUp();
    // mOutputStream.write(hexStringToByteArray("3bf01100ff01"));
  }

  public void powerDown() throws IOException, CadTransportException {

    System.out.println("Sending powerDown signal");
    mCadClient.powerDown(false);
  }

  public void exchangeTheAPDUWithSimulator() throws IOException, CadTransportException {

    // Exchange the APDUs
    System.out.println("data in length " + Utils.byteArrayToHexString(mApdu.dataIn) + " Lc = " + mApdu.Lc);
    mApdu.setDataIn(mApdu.dataIn, mApdu.Lc);
    mCadClient.exchangeApdu(mApdu);
    // mOutputStream.write(mApdu.command);

  }

  public void setAPDUCmds(byte[] cmds) {
    if (cmds.length > 4 || cmds.length == 0) {
      System.out.println("Invalid commands");
    } else {
      // Set the APDU header
      mApdu.command = cmds;
//			System.out.println("CLA: "+atrToHex(cmds[0]));
//			System.out.println("INS: "+atrToHex(cmds[1]));
//			System.out.println("P1: "+atrToHex(cmds[2]));
//			System.out.println("P2: "+atrToHex(cmds[3]));
    }
  }

  public void setDataLength(byte ln) {
    mApdu.Lc = Byte.toUnsignedInt(ln);
  }

  public void setTheDataIn(byte[] data) {
    if (data.length != mApdu.Lc) {
      System.err.println("The number of data in the array are more than expected");
    } else {
      // set the data to be sent to the applets
      mApdu.dataIn = data;
      /*
       * for (int dataIndx = 0; dataIndx < data.length; dataIndx++) {
       * System.out.println("dataIn" + dataIndx + ": " + atrToHex(data[dataIndx])); }
       */

    }
  }

  public void setExpctdByteLength(byte ln) {
    // expected length of the data in the response APDU
    mApdu.Le = Byte.toUnsignedInt(ln);
    System.out.println("Le: " + atrToHex(ln));
  }

  public String atrToHex(byte atCode) {
    char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    String str2 = "";
    int num = atCode & 0xff;
    int rem;
    while (num > 0) {
      rem = num % 16;
      str2 = hex[rem] + str2;
      num = num / 16;
    }
    if (str2 != "") {
      return str2;
    } else {
      return "0";
    }
  }

  public byte[] decodeDataOut() {
    byte[] dOut = mApdu.dataOut;
    return dOut;
  }

  public byte[] decodeStatus() {
    byte[] statByte = mApdu.getSw1Sw2();
    return statByte;
  }

  public boolean decodeApduBytes(byte[] apduBytes) {
    boolean isSuccess = false;
    if (apduBytes.length < 4) {
      System.out.println("apdubytes length less than 4");
      return isSuccess = false;
    }
    setAPDUCmds(Arrays.copyOfRange(apduBytes, 0, 4));

    // if apdu are of 5 bytes means last byte is of expected response length (Le
    // Field)
    if (apduBytes.length == 5) {
      setDataLength((byte) 0x00);
      setTheDataIn(new byte[] {});
      setExpctdByteLength(apduBytes[4]);
      return isSuccess = true;
    }

    // set data length (Lc field)
    if (apduBytes.length > 5) {
      setDataLength(apduBytes[4]);
      if (apduBytes[4] == 0) {
        setTheDataIn(new byte[] {});
      } else {
        setTheDataIn(Arrays.copyOfRange(apduBytes, 5, 5 + Byte.toUnsignedInt(apduBytes[4])));
      }
    }
    if (apduBytes.length == (4 + Byte.toUnsignedInt(apduBytes[4]) + 1)) {
      setExpctdByteLength(apduBytes[apduBytes.length - 1]);
    }

    return isSuccess = true;
  }
}
