import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import com.sun.javacard.apduio.CadTransportException;

/**
 * This program demonstrates a simple TCP/IP socket server.
 *
 * @author www.codejava.net
 */
public class JCServer {
  private static final String JCOP_PROVIDER = "jcop";
  private static final String JCOP_IDENTITY = "jcop_identity";
  private static final String JCARDSIM_PROVIDER = "jcardsim";
  private static final String JCARDSIM_IDENTITY = "jcardsim_identity";

  public static void main(String[] args) {
    if (args.length < 2) {
      System.out.println("Port no and provider name is expected as argument.");
      return;
    }

    int port = Integer.parseInt(args[0]);
    String providerName = args[1];
    Simulator simulator;
    if (JCOP_PROVIDER.equals(providerName)) {
      if (args.length < 5) {
        System.out.println("AppletAID, PackageAID and cap file path are expected as arguments for JCOP");
        return;
      }
      simulator = new JCOPSimulator(args[2], args[3], args[4]);
      Thread kmServer = new Thread(new AppletServer("Keymaster", simulator, port));
      kmServer.start();
    } else if (JCOP_IDENTITY.equals(providerName)) {
      if (args.length < 8) {
        System.out.println("Both keymaster and identity credential AppletAIDs, PackageAIDs and cap file paths are expected as arguments for JCOP Identity Credential.");
        return;
      }
      //simulator = new JCOPSimulator(args[2], args[3], args[4], args[5], args[6], args[7]);
      simulator = new JCOPSimulator(args[2], args[3], args[4]);
      Thread kmServer = new Thread(new AppletServer("Keymaster", simulator, port));
      kmServer.start();
      simulator = new JCOPSimulator(null, null, null, args[5], args[6], args[7]);
      Thread icServer = new Thread(new AppletServer("IdentityCredential", simulator, port + 10));
      icServer.start();
    } else if (JCARDSIM_PROVIDER.equals(providerName)) {
      simulator = new JCardSimulator();
      Thread kmServer = new Thread(new AppletServer("Keymaster-JCard", simulator, port));
      kmServer.start();
    } else if (JCARDSIM_IDENTITY.equals(providerName)) {
      simulator = new JCardSimIdentityCredential();
      Thread icServer = new Thread(new AppletServer("IdentityCredential-JCard", simulator, port + 10));
      icServer.start();
    } else {
      System.out.println("Unsupported provider.");
      return;
    }

  }

  public static class AppletServer implements Runnable {
    String appletName;
    Simulator simulator;
    int port;
    static boolean isICStarted;
    public AppletServer (String appletName, Simulator simulator, int port) {
      this.appletName = appletName;
      this.simulator = simulator;
      this.port = port;
    }

    @Override
    public void run() {
      handleConnection();
    }

    public void handleConnection() {
      try (ServerSocket serverSocket = new ServerSocket(port)) {
        simulator.initaliseSimulator();
        if (!simulator.setupKeymasterOnSimulator()) {
          System.out.println("Failed to setup Java card " + appletName + " simulator.");
          System.exit(-1);
        }

        byte[] outData;

        System.out.println("Listening on port :" + port);
        while (true) {
          try {
            Socket socket = serverSocket.accept();
            System.out.println("\n\n\n\n\n");
            System.out
                    .println(appletName + "------------------------New client connected on " + socket.getPort() + "--------------------");
            OutputStream output = null;
            InputStream isReader = null;
            try {
              socket.setReceiveBufferSize(1024 * 5);
              output = socket.getOutputStream();
              isReader = socket.getInputStream();

              byte[] inBytes = new byte[65536];
              int readLen = 0, index = 0;
              System.out.println("Socket input buffer size: " + socket.getReceiveBufferSize());
              while ((readLen = isReader.read(inBytes, index, 1024 * 5)) > 0) {
                if (readLen > 0) {
                  //System.out.println("Bytes read from index (" + index + ") socket: " + readLen + " Estimate read: "
                  //    + isReader.available());
                  byte[] outBytes;
                  try {
                    if(isICStarted && appletName.contains("Keymaster")) {
                      System.out.println("Ignoring Keymaster now");
                      output.write(new byte[]{(byte)0x90, 0x00});
                      output.flush();
                      continue;
                    }
                    if(!isICStarted && appletName.contains("IdentityCredential")) {
                      isICStarted = true;
                    }
                    if(simulator.setupKeymasterOnSimulator()) {
                      outBytes = simulator.executeApdu(Arrays.copyOfRange(inBytes, 0, index + readLen));
                      outData = simulator.decodeDataOut();
                      byte[] finalOutData = new byte[outData.length + outBytes.length];
                      System.arraycopy(outData, 0, finalOutData, 0, outData.length);
                      System.arraycopy(outBytes, 0, finalOutData, outData.length, outBytes.length);
                      //System.out.println("Return Data = " + Utils.byteArrayToHexString(finalOutData));
                      output.write(finalOutData);
                      output.flush();
                      index = 0;
                    } else {
                      System.out.println("Failed to select " + appletName + " applet");
                    }
                  } catch (IllegalArgumentException e) {
                    e.printStackTrace();
                    index = readLen;
                  }
                }
              }
            } catch (IOException e) {
              e.printStackTrace();
            } catch (Exception e) {
              e.printStackTrace();
            } finally {
              if (output != null)
                output.close();
              if (isReader != null)
                isReader.close();
              socket.close();
            }
          } catch (IOException e) {
            break;
          } catch (Exception e) {
            break;
          }
          System.out.println("Client disconnected for " + appletName);
        }
//			}
        simulator.disconnectSimulator();
      } catch (IOException ex) {
        System.out.println("Server exception: " + ex.getMessage());
        ex.printStackTrace();
      } catch (CadTransportException e1) {
        e1.printStackTrace();
      } catch (Exception e1) {
        e1.printStackTrace();
      }
    }
  }
}