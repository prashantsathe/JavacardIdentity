import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class ScriptParser {
  public static ArrayList<byte[]> getApdusFromScript(String scriptFilePath) {
    FileInputStream stream = null;
    try {
      stream = new FileInputStream(scriptFilePath);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
    String strLine;
    ArrayList<byte[]> apduList = new ArrayList<byte[]>();
    try {
      while ((strLine = reader.readLine()) != null) {
        if (!strLine.trim().startsWith("0x")) {
          continue;
        }
        strLine = strLine.replaceAll(" 0x|0x|;", "");// .replaceAll("0x", "").replaceAll(";", "");
        System.out.println("Converting = " + strLine);
        apduList.add(Utils.hexStringToByteArray(strLine));
      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      try {
        reader.close();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return apduList;
  }

}
