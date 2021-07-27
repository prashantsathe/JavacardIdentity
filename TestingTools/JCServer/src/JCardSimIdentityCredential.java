import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import android.security.jcic.JCardSimJCICStoreApplet;
import javacard.framework.AID;

public class JCardSimIdentityCredential implements Simulator {
	private CardSimulator simulator;
	private ResponseAPDU response;
	static final String AID = "A00000006203020C010102";

	public JCardSimIdentityCredential() {
	    simulator = new CardSimulator();
	}
	
	@Override
	public void initaliseSimulator() throws Exception {
	    AID appletAID1 = AIDUtil.create(AID);
	    //simulator.installApplet(appletAID1, KMJCardSimApplet.class);
	    System.out.println("Initializing JCardSimJCICStoreApplet.");
	    simulator.installApplet(appletAID1, JCardSimJCICStoreApplet.class);
	}

	@Override
	public void disconnectSimulator() throws Exception {
	    AID appletAID1 = AIDUtil.create(AID);
	    // Delete i.e. uninstall applet
	    simulator.deleteApplet(appletAID1);
	}

	@Override
	public boolean setupKeymasterOnSimulator() throws Exception {
	    AID appletAID1 = AIDUtil.create(AID);
	    // Select applet
	    //simulator.selectApplet(appletAID1);
	    // provision attest key
	    // return provisionCmd(simulator);// && setBootParams(simulator);
	    return true;
	}

	private final byte[] intToByteArray(int value) {
	  return new byte[] { (byte) (value >>> 8), (byte) value };
	}

	@Override
	public byte[] executeApdu(byte[] apdu) throws Exception {
	    CommandAPDU apduCmd = new CommandAPDU(apdu);
	    response = simulator.transmitCommand(apduCmd);
		System.out.println("Executing APDU = " + Utils.byteArrayToHexString(apdu));
		if(!Utils.byteArrayToHexString(intToByteArray(response.getSW())).equals("9000")) {
			System.out.println("Status = " + Utils.byteArrayToHexString(intToByteArray(response.getSW())));
		}
	    return intToByteArray(response.getSW());
	}

	@Override
	public byte[] decodeDataOut() {
	    return response.getData();
	}

}
