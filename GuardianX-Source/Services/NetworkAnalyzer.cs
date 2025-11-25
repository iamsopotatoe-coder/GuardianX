using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using SecureTaskManager.Models;

namespace SecureTaskManager.Services
{
    public class NetworkAnalyzer
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tblClass, int reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UDP_TABLE_CLASS tblClass, int reserved);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public int owningPid;
        }

        public List<NetworkConnection> GetAllConnections()
        {
            var connections = new List<NetworkConnection>();
            
            try
            {
                connections.AddRange(GetTcpConnections());
                connections.AddRange(GetUdpConnections());
                
                // Analyze connections for threats
                foreach (var conn in connections)
                {
                    AnalyzeConnectionThreat(conn);
                }
            }
            catch { }

            return connections.OrderByDescending(c => c.IsSuspicious).ThenBy(c => c.ProcessId).ToList();
        }

        private void AnalyzeConnectionThreat(NetworkConnection connection)
        {
            connection.IsSuspicious = false;
            connection.ThreatIndicator = "";

            // Check for suspicious remote ports (common malware C&C ports)
            var suspiciousPorts = new[] { 4444, 5555, 6666, 7777, 8080, 31337, 12345, 54321, 1337, 6667 };
            if (suspiciousPorts.Contains(connection.RemotePort))
            {
                connection.IsSuspicious = true;
                connection.ThreatIndicator = "⚠";
            }

            // Check for connections to private IPs from non-standard processes
            if (connection.Protocol == "TCP" && connection.State == "ESTABLISHED")
            {
                if (IsPrivateIP(connection.RemoteAddress))
                {
                    // Private IPs are usually OK, but flag if from suspicious process
                }
                else if (connection.RemoteAddress != "*" && connection.RemoteAddress != "0.0.0.0")
                {
                    // External connection - check if process is suspicious
                    var suspiciousProcesses = new[] { "cmd", "powershell", "wscript", "cscript", "rundll32" };
                    if (suspiciousProcesses.Any(p => connection.ProcessName.Equals(p, StringComparison.OrdinalIgnoreCase)))
                    {
                        connection.IsSuspicious = true;
                        connection.ThreatIndicator = "⚠";
                    }
                }
            }

            // Check for IRC ports (often used by botnets)
            if (connection.RemotePort >= 6660 && connection.RemotePort <= 6669)
            {
                connection.IsSuspicious = true;
                connection.ThreatIndicator = "⚠";
            }

            // Check for multiple connections from same process to different IPs (possible scanning)
            // This would require tracking state across calls, so we'll skip for now
        }

        private bool IsPrivateIP(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress) || ipAddress == "*")
                return false;

            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();

                // Check private IP ranges
                return (bytes[0] == 10) ||
                       (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                       (bytes[0] == 192 && bytes[1] == 168) ||
                       (bytes[0] == 127); // localhost
            }
            catch
            {
                return false;
            }
        }

        public void TerminateConnection(NetworkConnection connection)
        {
            // Note: Windows doesn't provide a direct API to kill connections
            // We can kill the process instead
            try
            {
                var process = Process.GetProcessById(connection.ProcessId);
                process.Kill();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to terminate connection: {ex.Message}");
            }
        }

        private List<NetworkConnection> GetTcpConnections()
        {
            var connections = new List<NetworkConnection>();
            IntPtr tcpTable = IntPtr.Zero;
            int buffSize = 0;

            try
            {
                GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                tcpTable = Marshal.AllocHGlobal(buffSize);

                uint ret = GetExtendedTcpTable(tcpTable, ref buffSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0)
                    return connections;

                int rowCount = Marshal.ReadInt32(tcpTable);
                IntPtr rowPtr = (IntPtr)((long)tcpTable + 4);

                for (int i = 0; i < rowCount; i++)
                {
                    MIB_TCPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    
                    var connection = new NetworkConnection
                    {
                        ProcessId = row.owningPid,
                        ProcessName = GetProcessName(row.owningPid),
                        Protocol = "TCP",
                        LocalAddress = new IPAddress(row.localAddr).ToString(),
                        LocalPort = (row.localPort1 << 8) + row.localPort2,
                        RemoteAddress = new IPAddress(row.remoteAddr).ToString(),
                        RemotePort = (row.remotePort1 << 8) + row.remotePort2,
                        State = GetTcpState(row.state)
                    };

                    connections.Add(connection);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                }
            }
            catch { }
            finally
            {
                if (tcpTable != IntPtr.Zero)
                    Marshal.FreeHGlobal(tcpTable);
            }

            return connections;
        }

        private List<NetworkConnection> GetUdpConnections()
        {
            var connections = new List<NetworkConnection>();
            IntPtr udpTable = IntPtr.Zero;
            int buffSize = 0;

            try
            {
                GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                udpTable = Marshal.AllocHGlobal(buffSize);

                uint ret = GetExtendedUdpTable(udpTable, ref buffSize, true, 2, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                if (ret != 0)
                    return connections;

                int rowCount = Marshal.ReadInt32(udpTable);
                IntPtr rowPtr = (IntPtr)((long)udpTable + 4);

                for (int i = 0; i < rowCount; i++)
                {
                    MIB_UDPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    
                    var connection = new NetworkConnection
                    {
                        ProcessId = row.owningPid,
                        ProcessName = GetProcessName(row.owningPid),
                        Protocol = "UDP",
                        LocalAddress = new IPAddress(row.localAddr).ToString(),
                        LocalPort = (row.localPort1 << 8) + row.localPort2,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = "N/A"
                    };

                    connections.Add(connection);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_UDPROW_OWNER_PID)));
                }
            }
            catch { }
            finally
            {
                if (udpTable != IntPtr.Zero)
                    Marshal.FreeHGlobal(udpTable);
            }

            return connections;
        }

        private string GetProcessName(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return process.ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }

        private string GetTcpState(uint state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTENING";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RECEIVED";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT_1";
                case 7: return "FIN_WAIT_2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "UNKNOWN";
            }
        }
    }
}
