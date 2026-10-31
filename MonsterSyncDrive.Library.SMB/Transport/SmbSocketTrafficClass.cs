/*
 * MIT License
 *
 * Copyright (c) 2025 - 2026 MonsterSyncDrive.Com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
using System.ComponentModel;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace MonsterSyncDrive.SMB.Transport;

/// <summary>应用操作系统提供的实际 DSCP 配置，并在套接字存活期间保留 Windows QoS 流。</summary>
internal static class SmbSocketTrafficClass
{
    /// <summary>在托管套接字存活期间，维持对应原生 qWAVE 句柄的有效性。</summary>
    private static readonly ConditionalWeakTable<Socket, SafeQosHandle> flows = new();

    /// <summary>通过 Windows QoS2 或 Unix 流量类别套接字选项请求六位 DSCP 值。</summary>
    /// <param name="socket">已经连接的 IPv4 或 IPv6 套接字。</param>
    /// <param name="dscp">不包含 ECN 位的六位 DSCP 值。</param>
    /// <exception cref="Win32Exception">Windows QoS 策略、权限或配置拒绝了请求。</exception>
    /// <exception cref="SocketException">Unix 套接字拒绝了流量类别设置。</exception>
    /// <exception cref="PlatformNotSupportedException">当前平台没有受支持的操作系统配置接口。</exception>
    internal static void Apply(Socket socket, int dscp)
    {
        if (dscp is < 0 or > 63) throw new ArgumentOutOfRangeException(nameof(dscp));
        if (OperatingSystem.IsWindows())
        {
            // 当前 Windows 上的 IP_TOS 不能可靠地设置 DSCP，因此使用显式
            // 配置的非自适应 qWAVE 流，并保留权限或策略错误。
            var version = new QosVersion { Major = 1 };
            if (!QOSCreateHandle(ref version, out var handle)) throw new Win32Exception(Marshal.GetLastPInvokeError(), "Windows QoS initialization failed.");
            try
            {
                uint flow = 0;
                if (!QOSAddSocketToFlow(handle, socket.SafeHandle, IntPtr.Zero, 0, 2, ref flow))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "Windows QoS flow creation failed.");
                var value = (uint)dscp;
                if (!QOSSetFlow(handle, flow, 2, 4, ref value, 0, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "Windows rejected the requested DSCP value.");
                // 关闭该句柄会移除对应的流；因此在 TCP 传输被释放之前始终保留句柄，
                // 包括套接字已经成功连接、但未在竞速中被选中的情况。
                flows.Add(socket, handle);
            }
            catch { handle.Dispose(); throw; }
        }
        else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            // 不同 Unix ABI 的原生选项标识不同；将 DSCP 左移两位以清空 ECN 位。
            // IPv4 TOS 和 IPv6 流量类别承载相同的六位 DSCP 字段。
            var value = dscp << 2;
            var ipv6 = socket.AddressFamily == AddressFamily.InterNetworkV6;
            var option = ipv6 ? (OperatingSystem.IsLinux() ? 67 : 36) : (OperatingSystem.IsLinux() ? 1 : 3);
            if (SetSocketOption(socket.SafeHandle, ipv6 ? 41 : 0, option, ref value, 4) != 0)
                throw new SocketException(Marshal.GetLastPInvokeError());
        }
        else throw new PlatformNotSupportedException("This platform does not expose a supported DSCP socket configuration API.");
    }

    /// <summary>关闭套接字之前释放可能存在的 Windows QoS 流；允许重复调用。</summary>
    /// <param name="tcp">由传输层持有的 TCP 客户端。</param>
    internal static void Dispose(TcpClient tcp)
    {
        var socket = tcp.Client;
        if (socket is not null && flows.TryGetValue(socket, out var flow)) { flows.Remove(socket); flow.Dispose(); }
        tcp.Dispose();
    }

    /// <summary>QOSCreateHandle 所要求的原生 QOS_VERSION 内存布局。</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct QosVersion
    {
        /// <summary>请求的 QoS2 API 主版本号。</summary>
        internal ushort Major;
        /// <summary>请求的 QoS2 API 次版本号。</summary>
        internal ushort Minor;
    }
    /// <summary>持有 qWAVE 句柄；关闭句柄时也会移除全部关联流。</summary>
    private sealed class SafeQosHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        /// <summary>为原生输出参数创建初始无效的句柄对象。</summary>
        public SafeQosHandle() : base(true) { }
        /// <summary>释放 qWAVE 资源，避免在安全句柄终结期间抛出异常。</summary>
        /// <returns>原生句柄是否成功关闭。</returns>
        protected override bool ReleaseHandle() => QOSCloseHandle(handle);
    }

    /// <summary>创建指定版本的原生 qWAVE 会话；BOOL 使用显式 Win32 编组。</summary>
    /// <param name="version">请求的 QoS2 API 版本。</param>
    /// <param name="handle">接收由托管代码持有的会话句柄。</param>
    /// <returns>成功时为 true；失败时可获取 Win32 最后错误码。</returns>
    [DllImport("qwave.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QOSCreateHandle(ref QosVersion version, out SafeQosHandle handle);
    /// <summary>关闭 qWAVE 会话并移除其关联流。</summary>
    /// <param name="handle">原生会话句柄。</param>
    /// <returns>会话成功关闭时为 true。</returns>
    [DllImport("qwave.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QOSCloseHandle(IntPtr handle);
    /// <summary>将已连接的套接字加入实际的 qWAVE 流。</summary>
    /// <param name="handle">持有该流的会话。</param>
    /// <param name="socket">已连接的套接字，在原生调用期间保持安全句柄有效。</param>
    /// <param name="destination">套接字已经连接时传入 null。</param>
    /// <param name="trafficType">原生流量类别。</param>
    /// <param name="flags">不请求路径探测时传入 QOS_NON_ADAPTIVE_FLOW。</param>
    /// <param name="flow">输入时为零，输出时接收所创建的流标识符。</param>
    /// <returns>成功时为 true。</returns>
    [DllImport("qwave.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QOSAddSocketToFlow(SafeQosHandle handle, SafeSocketHandle socket, IntPtr destination, int trafficType, uint flags, ref uint flow);
    /// <summary>设置流的出站 DSCP 值，并保留操作系统返回的权限错误。</summary>
    /// <param name="handle">持有该流的会话。</param>
    /// <param name="flow">流标识符。</param>
    /// <param name="operation">传入 QOSSetOutgoingDSCPValue。</param>
    /// <param name="size">原生 DWORD 的大小。</param>
    /// <param name="value">请求的 DSCP DWORD 值。</param>
    /// <param name="flags">保留字段，传入零。</param>
    /// <param name="overlapped">同步配置时传入 null。</param>
    /// <returns>成功时为 true。</returns>
    [DllImport("qwave.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QOSSetFlow(SafeQosHandle handle, uint flow, int operation, uint size, ref uint value, uint flags, IntPtr overlapped);
    /// <summary>通过安全套接字句柄调用原生 Unix 套接字选项接口。</summary>
    /// <param name="socket">由安全句柄表示的套接字文件描述符。</param>
    /// <param name="level">传入 IPPROTO_IP 或 IPPROTO_IPV6。</param>
    /// <param name="name">平台特定的 TOS 或流量类别选项。</param>
    /// <param name="value">四字节套接字选项值。</param>
    /// <param name="size">选项值的字节长度。</param>
    /// <returns>成功时返回零，失败时返回负一并设置 errno。</returns>
    [DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)]
    private static extern int SetSocketOption(SafeSocketHandle socket, int level, int name, ref int value, uint size);
}