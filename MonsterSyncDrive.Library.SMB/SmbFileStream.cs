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
using System.Buffers;

namespace MonsterSyncDrive.SMB;

/// <summary>
/// 可定位的远端文件流，同一实例的游标操作串行执行；同步方法会阻塞等待网络操作。
/// 长度由打开时快照及本流写入维护，外部修改须通过 RefreshLengthAsync 重新查询。
/// </summary>
public sealed class SmbFileStream : Stream
{
    /// <summary>由本流持有并在释放时关闭的远端文件句柄。</summary>
    private readonly SmbFileHandle handle;
    /// <summary>打开时确定的托管读写能力，不改变服务器已经授予的访问权限。</summary>
    private readonly FileAccess access;
    /// <summary>保护位置、长度以及关闭操作的异步门，防止同一流发生游标竞争。</summary>
    private readonly SemaphoreSlim gate = new(1, 1);
    /// <summary>追加模式打开时的原始 EOF；普通流为零，是定位和截断允许的下界。</summary>
    private readonly long appendStart;
    /// <summary>本流的当前字节游标，仅在持有门时修改，并通过原子读取向属性公开。</summary>
    private long position;
    /// <summary>打开快照及本实例成功写入后维护的逻辑长度缓存。</summary>
    private long length;
    /// <summary>流释放状态；零表示可用，非零表示关闭已开始且不再接受新操作。</summary>
    private int disposed;
    /// <summary>返回底层远端句柄；直接操作该句柄不会自动更新此流的游标和长度缓存。</summary>
    public SmbFileHandle Handle => handle;

    /// <summary>使用已打开的磁盘文件句柄初始化流及追加边界，不再发送额外的打开请求。</summary>
    /// <param name="handle">转交给流管理生命周期的远端句柄。</param>
    /// <param name="access">允许本流使用的读写能力。</param>
    /// <param name="append">是否从打开时 EOF 开始且禁止定位到该边界之前。</param>
    internal SmbFileStream(SmbFileHandle handle, FileAccess access, bool append)
    {
        this.handle = handle; this.access = access;
        length = handle.InitialLength;
        appendStart = append ? length : 0;
        position = appendStart;
    }

    /// <summary>流和底层句柄未关闭，且以读或读写访问打开时返回 true。</summary>
    public override bool CanRead => !IsDisposed && access is FileAccess.Read or FileAccess.ReadWrite;
    /// <summary>流和底层句柄未关闭，且以写或读写访问打开时返回 true。</summary>
    public override bool CanWrite => !IsDisposed && access is FileAccess.Write or FileAccess.ReadWrite;
    /// <summary>未关闭的磁盘文件流支持定位；不代表连接中断时操作仍能成功。</summary>
    public override bool CanSeek => !IsDisposed;
    /// <summary>读取本流维护的长度快照；外部文件变化不会自动更新此值。</summary>
    /// <exception cref="ObjectDisposedException">流或底层句柄已经关闭。</exception>
    public override long Length { get { ThrowIfDisposed(); return Interlocked.Read(ref length); } }
    /// <summary>获取当前字节游标，或使用绝对定位修改游标；追加流不能退回原始追加边界之前。</summary>
    public override long Position
    {
        get { ThrowIfDisposed(); return Interlocked.Read(ref position); }
        set => Seek(value, SeekOrigin.Begin);
    }

    /// <summary>本流开始释放或底层句柄被独立关闭时，视为流已经关闭。</summary>
    private bool IsDisposed => Volatile.Read(ref disposed) != 0 || handle.IsClosed;
    /// <summary>在流或句柄已关闭时拒绝后续操作。</summary>
    /// <exception cref="ObjectDisposedException">本流不再可用。</exception>
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(IsDisposed, this);

    /// <summary>阻塞读取一块远端数据到数组片段，并推进流位置；允许短读。</summary>
    /// <param name="buffer">接收数据的数组。</param>
    /// <param name="offset">数组内的起始位置，不是远端文件偏移。</param>
    /// <param name="count">最多读取的字节数，实际单次请求仍受协商块大小限制。</param>
    /// <returns>实际读取字节数；EOF 或零长度请求返回零。</returns>
    /// <exception cref="NotSupportedException">流没有读取能力。</exception>
    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    }

    /// <summary>使用临时托管数组阻塞读取一块数据到调用方 Span，读取后清理并归还临时缓冲。</summary>
    /// <param name="buffer">接收远端数据的连续内存区域。</param>
    /// <returns>实际读取的字节数，可以小于缓冲长度。</returns>
    public override int Read(Span<byte> buffer)
    {
        var rented = ArrayPool<byte>.Shared.Rent(Math.Min(buffer.Length, handle.ReadSize));
        try
        {
            var read = Read(rented, 0, Math.Min(buffer.Length, rented.Length));
            rented.AsSpan(0, read).CopyTo(buffer);
            return read;
        }
        finally { ArrayPool<byte>.Shared.Return(rented, clearArray: true); }
    }

    /// <summary>异步读取数组片段，所有读取位置通过本流的游标门协调。</summary>
    /// <param name="buffer">接收数据的数组。</param>
    /// <param name="offset">数组片段起点。</param>
    /// <param name="count">最多读取的字节数。</param>
    /// <param name="cancellationToken">取消等待游标门或网络读取的令牌。</param>
    /// <returns>本次实际读取的字节数。</returns>
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateBufferArguments(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <summary>在当前游标异步读取至多一个协商数据块，只有成功读取后才推进游标。</summary>
    /// <param name="buffer">接收数据的内存区域。</param>
    /// <param name="cancellationToken">取消等待或远端读取的令牌。</param>
    /// <returns>实际读取的字节数；文件结尾返回零。</returns>
    /// <exception cref="NotSupportedException">流没有读取能力。</exception>
    /// <exception cref="ObjectDisposedException">流或句柄已关闭。</exception>
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanRead)
            throw new NotSupportedException("The stream was not opened for reading.");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var read = await handle.ReadAsync(buffer, position, cancellationToken).ConfigureAwait(false);
            position += read;
            return read;
        }
        finally { gate.Release(); }
    }

    /// <summary>阻塞写入数组片段的全部数据，按每个服务器确认结果推进位置。</summary>
    /// <param name="buffer">包含待写数据的数组。</param>
    /// <param name="offset">源数组片段起点，不是远端文件偏移。</param>
    /// <param name="count">需要写入的总字节数。</param>
    /// <remarks>后续块失败时，之前确认写入的数据和游标进度不会回滚。</remarks>
    public override void Write(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    }

    /// <summary>通过临时托管数组分块阻塞写入 Span，归还缓冲时清理其内容。</summary>
    /// <param name="buffer">需要写入的全部源数据。</param>
    /// <exception cref="NotSupportedException">流没有写入能力。</exception>
    /// <remarks>方法不是原子文件替换；部分块成功后发生错误时，成功部分仍保留。</remarks>
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ThrowIfDisposed();
        if (!CanWrite)
            throw new NotSupportedException("The stream was not opened for writing.");
        var rented = ArrayPool<byte>.Shared.Rent(Math.Min(Math.Max(1, buffer.Length), handle.WriteSize));
        try
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var count = Math.Min(rented.Length, buffer.Length - offset);
                buffer.Slice(offset, count).CopyTo(rented);
                Write(rented, 0, count);
                offset += count;
            }
        }
        finally { ArrayPool<byte>.Shared.Return(rented, clearArray: true); }
    }

    /// <summary>异步写入数组片段的全部数据，底层按协商大小和实际短写结果继续提交。</summary>
    /// <param name="buffer">源数据数组。</param>
    /// <param name="offset">数组内起始位置。</param>
    /// <param name="count">本次需要写入的字节数。</param>
    /// <param name="cancellationToken">取消等待和后续写入的令牌，不撤销已确认数据。</param>
    /// <returns>全部字节均被服务器确认后的任务。</returns>
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateBufferArguments(buffer, offset, count);
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <summary>持有游标门异步写入全部数据，并在每次成功确认后更新位置和缓存长度。</summary>
    /// <param name="buffer">待写入的全部源内存。</param>
    /// <param name="cancellationToken">取消本次等待和网络写入的令牌。</param>
    /// <returns>全部数据均写入后的任务。</returns>
    /// <exception cref="NotSupportedException">流没有写入能力。</exception>
    /// <exception cref="IOException">写入范围超过 long 所能表示的文件偏移，或网络操作失败。</exception>
    /// <remarks>取消或后续块失败时保留已经确认的进度，不把部分写入报告成未执行。</remarks>
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanWrite)
            throw new NotSupportedException("The stream was not opened for writing.");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (position > long.MaxValue - buffer.Length)
                throw new IOException("The write would exceed the maximum file size.");
            var written = 0;
            while (written < buffer.Length)
            {
                // 每个短写确认都立即推进位置，避免后续块失败后把已提交数据隐藏成“完全未写入”。
                var count = await handle.WriteAsync(buffer[written..], position, cancellationToken: cancellationToken).ConfigureAwait(false);
                written += count;
                position += count;
                length = Math.Max(length, position);
            }
        }
        finally { gate.Release(); }
    }

    /// <summary>在流内定位，不发送服务器请求；基于末尾定位时使用当前缓存长度。</summary>
    /// <param name="offset">相对指定基准的有符号字节偏移。</param>
    /// <param name="origin">文件起点、当前游标或缓存 EOF。</param>
    /// <returns>定位后的绝对字节位置。</returns>
    /// <exception cref="ArgumentOutOfRangeException">定位基准无效。</exception>
    /// <exception cref="IOException">加法溢出，或定位到文件及追加边界之前。</exception>
    public override long Seek(long offset, SeekOrigin origin)
    {
        ThrowIfDisposed();
        gate.Wait();
        try
        {
            ThrowIfDisposed();
            long newPosition;
            try
            {
                newPosition = origin switch
                {
                    SeekOrigin.Begin => offset,
                    SeekOrigin.Current => checked(position + offset),
                    SeekOrigin.End => checked(length + offset),
                    _ => throw new ArgumentOutOfRangeException(nameof(origin))
                };
            }
            catch (OverflowException ex) { throw new IOException("The seek offset is outside the file range.", ex); }
            if (newPosition < appendStart)
                throw new IOException("The seek would move before the start of the file or append region.");
            position = newPosition;
            return position;
        }
        finally { gate.Release(); }
    }

    /// <summary>阻塞设置远端逻辑长度，并在必要时将本流游标收回到新的 EOF。</summary>
    /// <param name="value">新的非负逻辑字节长度，追加模式不得小于原始追加起点。</param>
    public override void SetLength(long value) => SetLengthAsync(value).GetAwaiter().GetResult();

    /// <summary>异步设置远端 EOF，成功后更新缓存长度，并将超出新 EOF 的游标向内收回。</summary>
    /// <param name="value">新的逻辑字节长度。</param>
    /// <param name="cancellationToken">取消等待游标门或长度设置的令牌。</param>
    /// <returns>服务器确认 EOF 设置的任务。</returns>
    /// <exception cref="ArgumentOutOfRangeException">长度为负数。</exception>
    /// <exception cref="NotSupportedException">流没有写入能力。</exception>
    /// <exception cref="IOException">追加流试图截断原始追加区域。</exception>
    public async Task SetLengthAsync(long value, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanWrite)
            throw new NotSupportedException("The stream was not opened for writing.");
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value < appendStart)
            throw new IOException("An append stream cannot truncate the existing append region.");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await handle.SetLengthAsync(value, cancellationToken).ConfigureAwait(false);
            length = value;
            if (position > value)
                position = value;
        }
        finally { gate.Release(); }
    }

    /// <summary>重新查询远端文件长度并替换本流的缓存长度，不自动改变当前位置。</summary>
    /// <param name="cancellationToken">取消等待或元数据查询的令牌。</param>
    /// <returns>服务器最新报告的逻辑文件长度。</returns>
    public async Task<long> RefreshLengthAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var info = await handle.GetInfoAsync(cancellationToken).ConfigureAwait(false);
            length = info.Length;
            return length;
        }
        finally { gate.Release(); }
    }

    /// <summary>阻塞发送 SMB FLUSH，等待服务器确认刷新当前文件。</summary>
    public override void Flush() => FlushAsync().GetAwaiter().GetResult();

    /// <summary>在持有游标门时异步请求服务器刷新文件，避免与本流写入交错。</summary>
    /// <param name="cancellationToken">取消等待或刷新请求的令牌。</param>
    /// <returns>服务器确认刷新操作的任务；介质持久化保证由服务器和存储实现决定。</returns>
    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await handle.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    /// <summary>实现 Stream 同步释放入口；托管释放时等待异步句柄关闭完成。</summary>
    /// <param name="disposing">是否执行托管资源释放。</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        base.Dispose(disposing);
    }

    /// <summary>幂等地关闭流，等待正在使用游标的操作退出后释放远端文件句柄。</summary>
    /// <returns>底层句柄关闭并完成本地释放的任务。</returns>
    /// <remarks>先标记关闭可使等待中的新操作失败；游标门不提前销毁，以便已进入的调用安全退出。</remarks>
    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        await gate.WaitAsync().ConfigureAwait(false);
        try { await handle.DisposeAsync().ConfigureAwait(false); }
        finally { gate.Release(); GC.SuppressFinalize(this); }
    }
}