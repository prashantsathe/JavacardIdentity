
public class JCOPSimulator implements Simulator {

  private static JCOPOpenCard openCardSim = JCOPOpenCard.getInstance();

  private byte[] kmAppletId;
  private byte[] icAppletId;
  private byte[] kmPackageAid;
  private byte[] icPackageAid;
  private String kmCapFilePath;
  private String icCapFilePath;

  private opencard.core.terminal.ResponseAPDU response;

  public JCOPSimulator(String pckgAid, String appletAid, String capFilePath) {
    kmPackageAid = Utils.hexStringToByteArray(pckgAid);
    kmAppletId = Utils.hexStringToByteArray(appletAid);
    this.kmCapFilePath = capFilePath;
  }

  public JCOPSimulator(String kmPkgAid, String kmAppletAid, String kmCapFilePath, String icPkgAid, String icAppletAid, String icCapFilePath) {
    if(kmPkgAid != null && kmAppletAid != null && kmCapFilePath != null) {
      this.kmPackageAid = Utils.hexStringToByteArray(kmPkgAid);
      this.kmAppletId = Utils.hexStringToByteArray(kmAppletAid);
      this.kmCapFilePath = kmCapFilePath;
    }
    if(icPkgAid != null && icAppletAid != null && icCapFilePath != null) {
      this.icPackageAid = Utils.hexStringToByteArray(icPkgAid);
      this.icAppletId = Utils.hexStringToByteArray(icAppletAid);
      this.icCapFilePath = icCapFilePath;
    }
  }

  @Override
  public void initaliseSimulator() throws Exception {
    synchronized (openCardSim) {
      if (!openCardSim.isConnected()) {
        try {
          openCardSim.connect();
          if (kmCapFilePath != null) {
            //In-case applets are installed from eclipse for debug purpose comment below line
            openCardSim.installApplet(kmCapFilePath, kmAppletId, kmPackageAid);
          }
          if (icCapFilePath != null) {
            //In-case applets are installed from eclipse for debug purpose comment below line
            openCardSim.installApplet(icCapFilePath, icAppletId, icPackageAid);
          }
        } catch (JCOPException e) {
          openCardSim.close();
          throw new JCOPException(e.getMessage());
        }
      }
    }
  }

  @Override
  public void disconnectSimulator() throws Exception {
    synchronized (openCardSim) {
      if (kmCapFilePath != null) {
        openCardSim.deleteApplet(kmPackageAid);
      }
      if (icCapFilePath != null) {
        openCardSim.deleteApplet(icPackageAid);
      }
    }
    openCardSim.close();
  }

  @Override
  public boolean setupKeymasterOnSimulator() throws Exception {
    synchronized (openCardSim) {
      if (kmCapFilePath != null) {
        openCardSim.selectApplet(kmAppletId);
      }
      if (icCapFilePath != null) {
        //openCardSim.selectApplet(icAppletId); IC applet is selected from HAL.
      }
    }
    return true;
  }

  private final byte[] intToByteArray(int value) {
    return new byte[] { (byte) (value >>> 8), (byte) value };
  }

  private javax.smartcardio.CommandAPDU validateApdu(byte[] apdu) throws IllegalArgumentException {
    javax.smartcardio.CommandAPDU apduCmd = new javax.smartcardio.CommandAPDU(apdu);
    return apduCmd;
  }

  @Override
  public byte[] executeApdu(byte[] apdu) throws Exception {
    System.out.println("Executing APDU = " + Utils.byteArrayToHexString(apdu));
    if (null == validateApdu(apdu)) {
      throw new IllegalArgumentException();
    }
    opencard.core.terminal.CommandAPDU cmdApdu = new opencard.core.terminal.CommandAPDU(apdu);
    synchronized (openCardSim) {
      response = openCardSim.transmitCommand(cmdApdu);
    }
    if(response.sw() != 36864 || Utils.byteArrayToHexString(apdu).startsWith("8015")) {
      System.out.println("Response = " + Utils.byteArrayToHexString(response.getBytes()));
    }
    return intToByteArray(response.sw());
  }

  private byte[] processApdu(byte[] apdu) {
    if (apdu[4] == 0x00 && apdu.length > 256) {
      byte[] returnApdu = new byte[apdu.length - 3];
      for (int i = 0; i < returnApdu.length; i++)
        returnApdu[i] = apdu[i];
      return returnApdu;// Expecting incoming apdu is already extended apdu
    }
    if (apdu.length == 6 && apdu[4] == (byte) 0 && apdu[5] == (byte) 0) {
      byte[] returnApdu = new byte[5];
      for (int i = 0; i < 5; i++)
        returnApdu[i] = apdu[i];
      return returnApdu;
    } else {
      // return apdu;
    }
    if (apdu[4] == (byte) 0)
      return apdu;
    byte[] finalApdu = new byte[apdu.length + 1];
    System.out.println("Incoming APDU = " + Utils.byteArrayToHexString(apdu));
    for (int i = 0; i < apdu.length; i++) {
      if (i < 4) {
        finalApdu[i] = apdu[i];
      } else if (i == apdu.length - 1 && apdu[i] == 0) {
      } else if (i > 4) {
        finalApdu[i + 2] = apdu[i];
      } else if (i == 4) {
        finalApdu[4] = (byte) 0;
        finalApdu[5] = (byte) 0x00;
        finalApdu[6] = apdu[i];
      }
    }
    return finalApdu;
  }

  @Override
  public byte[] decodeDataOut() {
    return response.getBytes();
  }

}
