package freenet.cli.subcommand;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import javax.management.MBeanServerInvocationHandler;
import javax.management.ObjectName;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import com.sun.jna.LastErrorException;
import com.sun.jna.Memory;
import com.sun.jna.Platform;
import com.sun.jna.platform.win32.IPHlpAPI;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import freenet.cli.mixin.IniPathOption;
import freenet.support.SimpleFieldSet;
import org.tanukisoftware.wrapper.jmx.WrapperManagerMBean;
import picocli.CommandLine;

@CommandLine.Command(name = "stop", description = "Stop Oldenet.")
public class Stop implements Callable<Integer> {

	@CommandLine.Spec
	CommandLine.Model.CommandSpec spec;

	@CommandLine.Mixin
	private IniPathOption iniPathOptionMixin;

	@Override
	public Integer call() throws Exception {

		var stopped = false;

		try (var br = Files.newBufferedReader(this.iniPathOptionMixin.iniPath)) {
			var sfs = new SimpleFieldSet(br, true, true);

			var listenPort = Integer.parseInt(sfs.get("node.listenPort"));
			var bindTo = sfs.get("node.bindTo");
			var addr = new InetSocketAddress(bindTo, listenPort);

			int pid = 0;

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

				}
				else {
					throw new LastErrorException("Error retrieving the socket table.");
				}
			}

			if (pid != 0) {

				// Try to find and attach to the VM

				List<VirtualMachineDescriptor> vms = VirtualMachine.list();

				for (VirtualMachineDescriptor desc : vms) {
					try {
						// The identifier is implementation-dependent but is typically the
						// process identifier (or pid) in environments where each Java
						// virtual
						// machine runs in its own operating system process.
						if (pid == Integer.parseInt(desc.id())) {
							// Attach to VM
							var vm = VirtualMachine.attach(desc.id());
							vm.startLocalManagementAgent();

							var props = vm.getAgentProperties();

							final String CONNECTOR_ADDRESS_PROP = "com.sun.management.jmxremote.localConnectorAddress";

							var connectorAddress = props.getProperty(CONNECTOR_ADDRESS_PROP);

							if (connectorAddress == null) {
								System.err.println("Unable to get vm local connector address.");
								break;
							}

							var url = new JMXServiceURL(connectorAddress);
							try (var connector = JMXConnectorFactory.connect(url)) {
								var mBeanConn = connector.getMBeanServerConnection();
								var mBeanName = new ObjectName("org.tanukisoftware.wrapper:type=WrapperManager");
								var wrapperManagerBean = (WrapperManagerMBean) MBeanServerInvocationHandler
										.newProxyInstance(mBeanConn, mBeanName, WrapperManagerMBean.class, false);

								wrapperManagerBean.stop(0);

								if (Platform.isWindows()) {
									var kernel32 = Kernel32.INSTANCE;

									var handle = kernel32.OpenProcess(WinNT.PROCESS_QUERY_LIMITED_INFORMATION, false,
											pid);

									for (var i = 0; i < 10; i++) {
										// Wait for the process to exit
										TimeUnit.SECONDS.sleep(1);

										var exitCode = new IntByReference();

										if (kernel32.GetExitCodeProcess(handle, exitCode)) {
											if (exitCode.getValue() != WinBase.STILL_ACTIVE) {
												stopped = true;
												break;
											}
										}
										else {
											throw new LastErrorException("Unable to GetExitCodeProcess()");
										}

									}

									kernel32.CloseHandle(handle);
								}

								if (stopped) {
									System.err.println("Stopped.");
									break;
								}
							}
							catch (IOException ex) {
								if (!stopped) {
									System.err.println("Unable to stop by JMX: " + ex.getMessage());
								}
							}
						}

					}
					catch (NumberFormatException ignored) {
						// Ignored and try next one
					}
					catch (AttachNotSupportedException ex) {
						System.err.println("Unable to attach vm: " + ex.getMessage());
						break;
					}
				}

				// TODO: Force stop pid
				// TODO: Stop service
			}
		}
		catch (IOException ex) {
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
