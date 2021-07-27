# TestingTools
JCServer is a testing tool, which provides a way to communicate with 
JCardSimulator/JCOPSimulator from android emulator/device.
It basically opens a socket connection on the port (port mentioned in program arguments)
and listens for the incomming data on this port. This tool uses apduio and JCardsim jars
to validate and transmit the APDUs to the Keymaster Applet. It also uses OpenCard Framework
to test with JCOP simulator.

### Build
Import JCServer server application either in Eclipse or IntelliJ. Add the provided jars inside
lib directory to the project and also add KeymasterApplet as
dependent project.

### Program Arguments
JCardSim: Add port number and provider name as arguments
Example:
<pre>
8080
jcardsim
</pre>

JCOP: Add port number, provider name, package AID, applet AID and CAP file path as
argumnets.
Example:
<pre>
8080
jcop
A00000006203020C0101
A00000006203020C010102
D:\KeymasterApplet\bin\com\android\javacard\keymaster\javacard\keymaster.cap 
</pre>
