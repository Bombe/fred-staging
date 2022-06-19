package freenet.cli.subcommand;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.concurrent.Callable;

import com.sun.jna.LastErrorException;
import com.sun.jna.Memory;
import com.sun.jna.Platform;
import com.sun.jna.platform.win32.IPHlpAPI;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.ptr.IntByReference;
import freenet.cli.mixin.IniPathOption;
import freenet.support.SimpleFieldSet;
import picocli.CommandLine;

@CommandLine.Command(name = "stop", description = "Stop Oldenet.")
public class Stop implements Callable<Integer> {

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    @CommandLine.Mixin
    private IniPathOption iniPathOptionMixin;

    @Override
    public Integer call() throws Exception {

        try (var br = Files.newBufferedReader(this.iniPathOptionMixin.iniPath)) {
            var sfs = new SimpleFieldSet(br, true, true);

            var listenPort = Integer.parseInt(sfs.get("node.listenPort"));
            var bindTo = sfs.get("node.bindTo");
            var addr = new InetSocketAddress(bindTo, listenPort);

            if (Platform.isWindows()) {
                // Find PID of ored process by bindTo and port number
                var ipHlpApi = IPHlpAPI.INSTANCE;

                var bufSize = new IntByReference();

                var check = ipHlpApi.GetExtendedUdpTable(null, bufSize, true, IPHlpAPI.AF_INET,
                        IPHlpAPI.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                if (check == WinError.ERROR_INSUFFICIENT_BUFFER) {
                    var pUdpTable = new Memory(bufSize.getValue());
                    var ret = ipHlpApi.GetExtendedUdpTable(pUdpTable, bufSize, true, IPHlpAPI.AF_INET,
                            IPHlpAPI.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

                    var udpTable = new IPHlpAPI.MIB_UDPTABLE_OWNER_PID(pUdpTable);

                    if (ret != WinError.NO_ERROR) {
                        throw new LastErrorException("Error retrieving the socket table.");
                    }

                    int pid;

                    for (IPHlpAPI.MIB_UDPROW_OWNER_PID row : udpTable.table) {

                        var processPort = convertPort(row.dwLocalPort);
                        var processAddr = InetAddress.getByAddress(ByteBuffer.allocate(Integer.BYTES)
                                .order(ByteOrder.LITTLE_ENDIAN).putInt(row.dwLocalAddr).array());

                        if (addr.getPort() == processPort
                                && (addr.isUnresolved() || addr.getAddress().equals(processAddr))) {
                            System.out.println("Addr: " + processAddr.getHostAddress());
                            System.out.println("Port: " + processPort);
                            System.out.println("PID: " + row.dwOwningPid);

                            pid = row.dwOwningPid;

                            break;
                        }

                    }

                } else {
                    throw new LastErrorException("Error retrieving the socket table.");
                }
            }
        } catch (IOException ex) {
            throw new CommandLine.ParameterException(this.spec.commandLine(),
                    "Unable to read freenet.ini file. Check whether --ini-path is correct and freenet.ini has proper permission set.",
                    ex, this.spec.findOption("--ini-path"), this.iniPathOptionMixin.iniPath.toString());
        }

        return 0;
    }

    private static int convertPort(int dwLocalPort) {
        var portBf = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(dwLocalPort);
        var portBytes = Arrays.copyOfRange(portBf.array(), 0, 2);
        var portBytesNew = new byte[Integer.BYTES];
        System.arraycopy(portBytes, 0, portBytesNew, 2, 2);
        return ByteBuffer.wrap(portBytesNew).getInt();
    }

}
