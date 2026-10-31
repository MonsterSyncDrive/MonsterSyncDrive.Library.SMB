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
using MonsterSyncDrive.Library.SMB.Protocol;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace MonsterSyncDrive.Library.SMB.Transport;

/// <summary>基于微软 ndspi.h 和 nddef.h 的 NetworkDirect v2 接口声明，兼容 AOT。</summary>
/// <remarks>
/// 接口来源：https://github.com/microsoft/NetworkDirect/tree/master/src/ndutil 。不使用 COM 运行时
/// 包装器或动态生成的封送代码。虚函数表槽位包含 IUnknown 的三个
/// 基础条目。指针调用隔离在本文件，由托管端点所有权约束其生命周期。
/// </remarks>
internal static unsafe partial class RdmaNativeNetworkDirect
{
    /// <summary>原生操作成功状态。</summary>
    internal const int Success = 0;
    /// <summary>NetworkDirect 异步操作的 STATUS_PENDING 值。</summary>
    internal const int Pending = 0x103;
    /// <summary>转换为 HRESULT 的 Win32 ERROR_IO_INCOMPLETE。</summary>
    internal const int Incomplete = unchecked((int)0x800703E4);
    /// <summary>要求的 NetworkDirect v2 提供程序版本。</summary>
    internal const int Version = 0x20000;
    /// <summary>ND2 适配器接口标识符。</summary>
    internal static readonly Guid AdapterId = new("d89c798c-4823-4d69-846c-dfdccff9e5f3");
    /// <summary>ND2 提供程序接口标识符。</summary>
    internal static readonly Guid ProviderId = new("49eae6c1-76c4-46d0-8003-5c2eaa2c9a8e");
    /// <summary>ND2 完成队列接口标识符。</summary>
    internal static readonly Guid CompletionQueueId = new("20cc445e-64a0-4cbb-aa75-f6a7251fda9e");
    /// <summary>ND2 队列对接口标识符。</summary>
    internal static readonly Guid QueuePairId = new("eef2f332-b75d-4063-bce3-3a0bad2d02ce");
    /// <summary>ND2 连接器接口标识符。</summary>
    internal static readonly Guid ConnectorId = new("7dd615c4-6b4c-4866-950c-f3b1d25a5302");
    /// <summary>ND2 已注册内存接口标识符。</summary>
    internal static readonly Guid MemoryRegionId = new("55dfea2f-bc56-4982-8a45-0301be46c413");

    /// <summary>严格对应 Windows SDK 的 WSAPROTOCOL_INFOW 布局，在 x64 上也保持固定宽度。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProtocolInfo
    {
        /// <summary>用于识别可靠消息提供程序的 XP1 能力。</summary>
        internal uint ServiceFlags1;
        /// <summary>附加的 Winsock 服务能力。</summary>
        internal uint ServiceFlags2;
        /// <summary>附加的 Winsock 服务能力。</summary>
        internal uint ServiceFlags3;
        /// <summary>附加的 Winsock 服务能力。</summary>
        internal uint ServiceFlags4;
        /// <summary>包含 PFL_HIDDEN 和 PFL_NETWORKDIRECT_PROVIDER 标志。</summary>
        internal uint ProviderFlags;
        /// <summary>提供程序目录中供 DllGetClassObject 使用的 CLSID。</summary>
        internal Guid Id;
        /// <summary>Winsock 目录条目标识符。</summary>
        internal uint CatalogEntryId;
        /// <summary>协议链长度。</summary>
        internal int ChainLength;
        /// <summary>SDK 定义的固定 MAX_PROTOCOL_CHAIN 条目。</summary>
        internal fixed uint ChainEntries[7];
        /// <summary>ND_VERSION_2 提供程序版本，不是 TCP/IP 版本。</summary>
        internal int ProviderVersion;
        /// <summary>地址族为 AF_INET 或 AF_INET6。</summary>
        internal int AddressFamily;
        /// <summary>sockaddr 的最大字节数。</summary>
        internal int MaximumAddressLength;
        /// <summary>sockaddr 的最小字节数。</summary>
        internal int MinimumAddressLength;
        /// <summary>ND 目录条目使用 -1，不使用 SOCK_STREAM。</summary>
        internal int SocketType;
        /// <summary>ND 目录条目使用零。</summary>
        internal int Protocol;
        /// <summary>ND 目录条目使用零。</summary>
        internal int MaximumProtocolOffset;
        /// <summary>原生网络字节序标记。</summary>
        internal int NetworkByteOrder;
        /// <summary>原生安全方案标识符。</summary>
        internal int SecurityScheme;
        /// <summary>原生最大消息长度。</summary>
        internal uint MessageSize;
        /// <summary>提供程序保留值。</summary>
        internal uint ProviderReserved;
        /// <summary>WSAPROTOCOL_LEN 长度加末尾 NUL 字符。</summary>
        internal fixed char Name[256];
    }

    /// <summary>ND2_ADAPTER_INFO；SIZE_T 字段采用进程原生指针宽度。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct AdapterInfo
    {
        /// <summary>请求的接口版本 ND_VERSION_2。</summary>
        internal uint InfoVersion;
        /// <summary>PCI 厂商标识符。</summary>
        internal ushort Vendor;
        /// <summary>PCI 设备标识符。</summary>
        internal ushort Device;
        /// <summary>提供程序定义的适配器标识符。</summary>
        internal ulong Id;
        /// <summary>可注册内存区域的最大长度。</summary>
        internal nuint MaximumRegistrationSize;
        /// <summary>远程内存窗口的最大长度。</summary>
        internal nuint MaximumWindowSize;
        /// <summary>发起方的散布与聚集容量。</summary>
        internal uint MaximumInitiatorSge;
        /// <summary>接收方的散布与聚集容量。</summary>
        internal uint MaximumReceiveSge;
        /// <summary>RDMA 读取的散布与聚集容量。</summary>
        internal uint MaximumReadSge;
        /// <summary>单个工作请求的最大字节数。</summary>
        internal uint MaximumTransferLength;
        /// <summary>内联发送的最大字节数。</summary>
        internal uint MaximumInlineDataSize;
        /// <summary>最大传入读取资源数量。</summary>
        internal uint MaximumInboundReadLimit;
        /// <summary>最大传出读取资源数量。</summary>
        internal uint MaximumOutboundReadLimit;
        /// <summary>一个队列对可容纳的最大接收工作请求数量。</summary>
        internal uint MaximumReceiveQueueDepth;
        /// <summary>一个队列对可容纳的最大发起方工作请求数量。</summary>
        internal uint MaximumInitiatorQueueDepth;
        /// <summary>共享接收队列的最大深度。</summary>
        internal uint MaximumSharedReceiveQueueDepth;
        /// <summary>完成队列中的最大完成条目数。</summary>
        internal uint MaximumCompletionQueueDepth;
        /// <summary>提供程序的内联阈值。</summary>
        internal uint InlineRequestThreshold;
        /// <summary>提供程序的大请求阈值。</summary>
        internal uint LargeRequestThreshold;
        /// <summary>连接请求私有数据的最大长度。</summary>
        internal uint MaximumCallerData;
        /// <summary>连接响应私有数据的最大长度。</summary>
        internal uint MaximumCalleeData;
        /// <summary>设备能力标志。</summary>
        internal uint AdapterFlags;
    }

    /// <summary>ND2_RESULT；RequestContext 是不透明整数标识，绝不存放托管对象指针。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct Result
    {
        /// <summary>完成结果中兼容 NTSTATUS 的 HRESULT。</summary>
        internal int Status;
        /// <summary>已完成的字节数。</summary>
        internal uint BytesTransferred;
        /// <summary>创建队列对时提供的不透明标识。</summary>
        internal nint QueuePairContext;
        /// <summary>工作请求的不透明标识。</summary>
        internal nint RequestContext;
        /// <summary>工作类型为接收、发送、绑定、失效、读取或写入。</summary>
        internal uint RequestType;
    }

    /// <summary>ND2_SGE；内存保持固定，直到原生操作完成且注销成功。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct Sge
    {
        /// <summary>已注册的本地虚拟地址。</summary>
        internal nint Buffer;
        /// <summary>字节长度。</summary>
        internal uint Length;
        /// <summary>提供程序的不透明本地注册令牌。</summary>
        internal uint Token;
    }

    /// <summary>OVERLAPPED 布局，原生联合体使用两个 DWORD 表示。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct Overlapped
    {
        /// <summary>保留的原生状态。</summary>
        internal nuint Internal;
        /// <summary>保留的原生字节数。</summary>
        internal nuint InternalHigh;
        /// <summary>联合体低位字段，ND 操作使用零。</summary>
        internal uint Offset;
        /// <summary>联合体高位字段，ND 操作使用零。</summary>
        internal uint OffsetHigh;
        /// <summary>在完成结果被收取前始终保持有效的事件句柄。</summary>
        internal nint Event;
    }

    /// <summary>初始化 Winsock，不依赖反射生成的封送代码。</summary>
    [LibraryImport("ws2_32.dll", EntryPoint = "WSAStartup")]
    internal static partial int WsaStartup(ushort version, nint data);
    /// <summary>释放一次对应的 Winsock 初始化引用。</summary>
    [LibraryImport("ws2_32.dll", EntryPoint = "WSACleanup")]
    internal static partial int WsaCleanup();
    /// <summary>枚举完整的提供程序目录，包括隐藏的 NetworkDirect 条目。</summary>
    [LibraryImport("ws2_32.dll", EntryPoint = "WSCEnumProtocols")]
    private static partial int EnumerateProtocols(nint protocols, nint buffer, ref uint length, out int error);
    /// <summary>读取目录中提供程序已安装的原生 DLL 路径。</summary>
    [LibraryImport("ws2_32.dll", EntryPoint = "WSCGetProviderPath")]
    private static partial int GetProviderPath(in Guid id, nint path, ref int length, out int error);
    /// <summary>创建 OVERLAPPED 事件；BOOL 参数使用符合接口宽度的 int 表示。</summary>
    [LibraryImport("kernel32.dll", EntryPoint = "CreateEventW", SetLastError = true)]
    internal static partial nint CreateEvent(nint attributes, int manualReset, int initialState, nint name);
    /// <summary>关闭拥有的内核句柄。</summary>
    [LibraryImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint handle);

    /// <summary>使用与微软辅助实现相同的目录筛选条件返回 NDv2 提供程序。</summary>
    internal static IReadOnlyList<(Guid Id, string Name, int Family, string Path)> Enumerate()
    {
        uint length = 0;
        _ = EnumerateProtocols(0, 0, ref length, out int error);
        if (length == 0)
        {
            return error is 0 or 10055 ? [] : throw new Win32Exception(error, "Could not query the Winsock provider catalog.");
        }
        if (length > 16 * 1024 * 1024)
            throw new IOException("An unreasonable Winsock catalog size was reported.");
        nint buffer = (nint)NativeMemory.Alloc(length);
        try
        {
            int count = EnumerateProtocols(0, buffer, ref length, out error);
            if (count < 0)
                throw new Win32Exception(error, "Could not enumerate NetworkDirect providers.");
            if ((ulong)count * (uint)sizeof(ProtocolInfo) > length)
                throw new IOException("Invalid Winsock catalog bounds.");
            List<(Guid, string, int, string)> result = new();
            for (int i = 0; i < count; i++)
            {
                var info = ((ProtocolInfo*)buffer)[i];
                if ((info.ServiceFlags1 & 0x8E) != 0x8E || (info.ProviderFlags & 0x11) != 0x11 || info.ProviderVersion != Version ||
                    info.AddressFamily is not (2 or 23) || info.SocketType != -1 || info.Protocol != 0 || info.MaximumProtocolOffset != 0)
                    continue;
                var providerId = info.Id;
                int providerFamily = info.AddressFamily;
                string path = PathFor(providerId);
                string name = new string(info.Name, 0, 256).TrimEnd('\0');
                if (!result.Any(item => item.Item1 == providerId && item.Item3 == providerFamily))
                    result.Add((providerId, name, providerFamily, path));
            }
            return result;
        }
        finally
        {
            NativeMemory.Free((void*)buffer);
        }
    }

    /// <summary>加载任何提供程序 DLL 前，解析并校验目录路径。</summary>
    private static string PathFor(Guid id)
    {
        int length = 32768;
        nint buffer = (nint)NativeMemory.Alloc((nuint)(length * sizeof(char)));
        try
        {
            if (GetProviderPath(in id, buffer, ref length, out int error) != 0)
                throw new Win32Exception(error, "Could not resolve a NetworkDirect provider DLL.");
            if (length is <= 0 or > 32768)
                throw new IOException("Invalid provider path length.");
            ReadOnlySpan<char> nativePath = new((void*)buffer, length);
            int terminator = nativePath.IndexOf('\0');
            if (terminator < 0)
                throw new IOException("The provider path was not NUL terminated.");
            string path = Environment.ExpandEnvironmentVariables(new string(nativePath[..terminator]));
            return !Path.IsPathFullyQualified(path)
                ? throw new IOException("The NetworkDirect provider catalog path is not absolute.")
                : Path.GetFullPath(path);
        }
        finally
        {
            NativeMemory.Free((void*)buffer);
        }
    }

    /// <summary>按照 ndprov.cpp 的要求，直接调用 ND2 专用的类对象导出函数。</summary>
    internal static nint GetProvider(nint module, Guid classId)
    {
        nint entry = NativeLibrary.GetExport(module, "DllGetClassObject");
        var iid = ProviderId;
        nint pointer = 0;
        Check(((delegate* unmanaged[Stdcall]<Guid*, Guid*, nint*, int>)entry)(&classId, &iid, &pointer), "DllGetClassObject(IND2Provider)");
        return pointer != 0 ? pointer : throw new IOException("The native ND2 provider returned a null interface.");
    }

    /// <summary>将请求的源地址解析为提供程序适配器标识符。</summary>
    internal static int Resolve(nint provider, ReadOnlySpan<byte> address, out ulong id)
    {
        fixed (byte* a = address)
        fixed (ulong* p = &id)
            return ((delegate* unmanaged[Stdcall]<nint, byte*, uint, ulong*, int>)Slot(provider, 4))(provider, a, (uint)address.Length, p);
    }
    /// <summary>使用解析出的标识符打开 ND2 适配器。</summary>
    internal static nint OpenAdapter(nint provider, ulong id)
    {
        var iid = AdapterId;
        nint result = 0;
        Check(((delegate* unmanaged[Stdcall]<nint, Guid*, ulong, nint*, int>)Slot(provider, 5))(provider, &iid, id, &result), "IND2Provider.OpenAdapter");
        return result;
    }
    /// <summary>创建本端点各 ND2 对象共用的异步文件句柄。</summary>
    internal static nint CreateFile(nint adapter)
    {
        nint file = 0;
        Check(((delegate* unmanaged[Stdcall]<nint, nint*, int>)Slot(adapter, 3))(adapter, &file), "IND2Adapter.CreateOverlappedFile");
        return file;
    }
    /// <summary>查询设备的硬件队列、内存和传输限制。</summary>
    internal static AdapterInfo Query(nint adapter)
    {
        AdapterInfo result = new()
        {
            InfoVersion = Version
        };
        uint size = (uint)sizeof(AdapterInfo);
        Check(((delegate* unmanaged[Stdcall]<nint, AdapterInfo*, uint*, int>)Slot(adapter, 4))(adapter, &result, &size), "IND2Adapter.Query");
        return size < sizeof(AdapterInfo) || result.InfoVersion != Version
            ? throw new IOException("An unsupported ND2 adapter info ABI was returned.")
            : result;
    }
    /// <summary>创建完成队列；组和亲和性均为零时由提供程序选择处理位置。</summary>
    internal static nint CreateCq(nint adapter, nint file, uint depth)
    {
        var iid = CompletionQueueId;
        nint result = 0;
        Check(((delegate* unmanaged[Stdcall]<nint, Guid*, nint, uint, ushort, nuint, nint*, int>)Slot(adapter, 6))(adapter, &iid, file, depth, 0, 0, &result), "IND2Adapter.CreateCompletionQueue");
        return result;
    }
    /// <summary>创建队列对，并用同一个完成队列接收发起方和接收方的完成结果。</summary>
    internal static nint CreateQp(nint adapter, nint cq, uint receiveDepth, uint initiatorDepth)
    {
        var iid = QueuePairId;
        nint result = 0;
        Check(((delegate* unmanaged[Stdcall]<nint, Guid*, nint, nint, nint, uint, uint, uint, uint, uint, nint*, int>)Slot(adapter, 10))
            (adapter, &iid, cq, cq, 0, receiveDepth, initiatorDepth, 1, 1, 0, &result), "IND2Adapter.CreateQueuePair");
        return result;
    }
    /// <summary>通过适配器接口创建异步连接器或内存区域。</summary>
    internal static nint CreateObject(nint adapter, nint file, Guid iid, int slot)
    {
        nint result = 0;
        Check(((delegate* unmanaged[Stdcall]<nint, Guid*, nint, nint*, int>)Slot(adapter, slot))(adapter, &iid, file, &result), "IND2Adapter.CreateObject");
        return result;
    }
    /// <summary>将 RDMA 连接器绑定到指定的本地地址和端口。</summary>
    internal static void Bind(nint connector, ReadOnlySpan<byte> address)
    {
        fixed (byte* a = address)
            Check(((delegate* unmanaged[Stdcall]<nint, byte*, uint, int>)Slot(connector, 5))(connector, a, (uint)address.Length), "IND2Connector.Bind");
    }
    /// <summary>开始原生可靠连接 RDMA 连接管理器交换。</summary>
    internal static int Connect(nint connector, nint qp, ReadOnlySpan<byte> remote, uint inboundReads, uint outboundReads, nint overlapped)
    {
        fixed (byte* a = remote)
            return ((delegate* unmanaged[Stdcall]<nint, nint, byte*, uint, uint, uint, nint, uint, nint, int>)Slot(connector, 6))
                (connector, qp, a, (uint)remote.Length, inboundReads, outboundReads, 0, 0, overlapped);
    }
    /// <summary>完成 ND2 主动端的连接建立。</summary>
    internal static int CompleteConnect(nint connector, nint overlapped)
    {
        return ((delegate* unmanaged[Stdcall]<nint, nint, int>)Slot(connector, 7))(connector, overlapped);
    }

    /// <summary>读取原生连接器的本地或对端套接字地址。</summary>
    internal static byte[] Address(nint connector, bool peer)
    {
        byte[] buffer = new byte[128];
        uint length = (uint)buffer.Length;
        fixed (byte* p = buffer)
            Check(((delegate* unmanaged[Stdcall]<nint, byte*, uint*, int>)Slot(connector, peer ? 13 : 12))(connector, p, &length), "IND2Connector.GetAddress");
        return length > buffer.Length || length < 16
            ? throw new IOException("Invalid native RDMA socket address.")
            : buffer.AsSpan(0, (int)length).ToArray();
    }
    /// <summary>开始异步内存注册；标志只授予请求的访问权限。</summary>
    internal static int Register(nint region, nint buffer, nuint length, uint flags, nint overlapped)
    {
        return ((delegate* unmanaged[Stdcall]<nint, nint, nuint, uint, nint, int>)Slot(region, 5))(region, buffer, length, flags, overlapped);
    }

    /// <summary>开始注销，等待远程访问栅栏生效后才允许解除缓冲区固定。</summary>
    internal static int Deregister(nint region, nint overlapped)
    {
        return ((delegate* unmanaged[Stdcall]<nint, nint, int>)Slot(region, 6))(region, overlapped);
    }

    /// <summary>返回本地或远程提供程序令牌，不解释其不透明位模式。</summary>
    internal static uint Token(nint region, bool remote)
    {
        return ((delegate* unmanaged[Stdcall]<nint, uint>)Slot(region, remote ? 8 : 7))(region);
    }

    /// <summary>投递 SEND 或 RECEIVE；请求标识保持有效，直到收到对应完成队列结果。</summary>
    internal static int Post(nint qp, nint cookie, Sge sge, bool receive)
    {
        return receive ? ((delegate* unmanaged[Stdcall]<nint, nint, Sge*, uint, int>)Slot(qp, 5))(qp, cookie, &sge, 1)
                : ((delegate* unmanaged[Stdcall]<nint, nint, Sge*, uint, uint, int>)Slot(qp, 4))(qp, cookie, &sge, 1, 0);
    }

    /// <summary>使用远程地址和导向令牌，投递真实设备 RDMA 读写。</summary>
    internal static int PostDirect(nint qp, nint cookie, Sge sge, SmbRdmaBufferDescriptor remote, bool write)
    {
        return ((delegate* unmanaged[Stdcall]<nint, nint, Sge*, uint, ulong, uint, uint, int>)Slot(qp, write ? 9 : 8))
                (qp, cookie, &sge, 1, remote.Offset, remote.Token, 0);
    }

    /// <summary>取得完成队列结果，不依赖回调或运行时 COM 封送。</summary>
    internal static uint Results(nint cq, Span<Result> results)
    {
        fixed (Result* p = results)
            return ((delegate* unmanaged[Stdcall]<nint, Result*, uint, uint>)Slot(cq, 8))(cq, p, (uint)results.Length);
    }
    /// <summary>清空队列对的全部未完成工作；释放内存前必须收取全部完成结果。</summary>
    internal static void Flush(nint qp)
    {
        Check(((delegate* unmanaged[Stdcall]<nint, int>)Slot(qp, 3))(qp), "IND2QueuePair.Flush");
    }

    /// <summary>取消该原生对象的异步操作。</summary>
    internal static void Cancel(nint obj)
    {
        _ = ((delegate* unmanaged[Stdcall]<nint, int>)Slot(obj, 3))(obj);
    }

    /// <summary>使用 ND2 的 HRESULT 返回约定，轮询或等待异步操作结束。</summary>
    internal static int OverlappedResult(nint obj, nint overlapped, bool wait)
    {
        return ((delegate* unmanaged[Stdcall]<nint, nint, int, int>)Slot(obj, 4))(obj, overlapped, wait ? 1 : 0);
    }

    /// <summary>相关操作栅栏完成后，释放一个拥有的原生 COM 引用。</summary>
    internal static void Release(nint obj)
    {
        if (obj != 0)
            _ = ((delegate* unmanaged[Stdcall]<nint, uint>)Slot(obj, 2))(obj);
    }
    /// <summary>取得虚函数表指针；整个调用期间调用方必须持有对象所有权引用。</summary>
    private static nint Slot(nint obj, int index)
    {
        return obj == 0 ? throw new ObjectDisposedException("NetworkDirect object") : (*(nint**)obj)[index];
    }

    /// <summary>将失败的原生状态转换为带操作上下文的托管输入输出错误。</summary>
    internal static void Check(int status, string operation)
    {
        if (status < 0)
            throw new IOException($"{operation} failed with native status 0x{(uint)status:X8}.", Marshal.GetExceptionForHR(status));
    }
    /// <summary>在可移动托管内存之外分配清零的 OVERLAPPED 存储。</summary>
    internal static nint AllocateOverlapped(nint @event)
    {
        Overlapped* pointer = (Overlapped*)NativeMemory.AllocZeroed((nuint)sizeof(Overlapped));
        pointer->Event = @event;
        return (nint)pointer;
    }
    /// <summary>只有完成结果已经收取后才释放 OVERLAPPED 存储。</summary>
    internal static void FreeOverlapped(nint pointer)
    {
        NativeMemory.Free((void*)pointer);
    }

    /// <summary>调用方保留固定内存句柄期间，返回其指针。</summary>
    internal static nint PinnedPointer(System.Buffers.MemoryHandle handle)
    {
        return (nint)handle.Pointer;
    }

    /// <summary>分配临时 WSADATA 存储，容量大于 Windows 两种接口布局。</summary>
    internal static nint AllocateWsaData()
    {
        return (nint)NativeMemory.AllocZeroed(512);
    }

    /// <summary>释放临时 WSADATA 存储。</summary>
    internal static void FreeWsaData(nint pointer)
    {
        NativeMemory.Free((void*)pointer);
    }
}