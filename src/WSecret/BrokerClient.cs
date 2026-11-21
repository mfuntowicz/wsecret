using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using Microsoft.Win32.SafeHandles;

namespace WSecret;

// ---------------------------------------------------------------------------
// Wire model (broker protocol v1, contract owner: wsecret-broker protocol.rs).
// All frames little-endian; payloads are packed sequential fields with no
// alignment padding except explicit pad bytes. Secrets NEVER appear in any
// response payload: values and TOTP codes are copied by the broker itself.
// ---------------------------------------------------------------------------

internal enum BrokerLifecycle : byte
{
    Locked = 0,
    Unlocking = 1,
    Unlocked = 2,
    Locking = 3,
}

internal enum HelloState : byte
{
    /// <summary>PRF/hmac-secret unavailable — Hello is fail-disabled.</summary>
    UnsupportedFailDisabled = 0,
    AvailableNotEnrolled = 1,
    Enrolled = 2,
}

/// <summary>
/// Broker status codes: core <c>Status::code()</c> verbatim for 0–25, plus
/// protocol-only codes at 0x100+.
/// </summary>
internal enum BrokerStatus : ushort
{
    Ok = 0,
    InvalidArgument = 1,
    InvalidName = 2,
    EntryTooBig = 3,
    StoreNotFound = 4,
    UnsupportedVersion = 6,
    MalformedStore = 7,
    ResourceLimit = 8,
    NotFound = 9,
    AlreadyExists = 10,
    PassphraseMismatch = 12,
    Locked = 13,

    /// <summary>CAS failure: the record moved/changed since the observed slot.</summary>
    Conflict = 15,
    Cancelled = 16,
    Io = 17,
    Crypto = 18,
    NoMemory = 19,
    MemoryProtection = 20,
    Panic = 23,
    CommitUncertain = 24,
    InvalidTotp = 25,

    // Protocol-only codes.
    VersionMismatch = 0x100,
    WrongState = 0x101,
    StaleGeneration = 0x102,
    Busy = 0x103,
    Timeout = 0x104,
    HelloUnavailable = 0x105,
    HelloNotEnrolled = 0x106,
    HelloFailed = 0x107,
    ClipboardError = 0x108,

    /// <summary>Binary value: copy refused (the UI copies text values only via broker clipboard).</summary>
    ValueNotText = 0x109,
    NoConsole = 0x10A,

    /// <summary>Broker prompt input rejected (too long / control bytes / invalid UTF-16).</summary>
    InputInvalid = 0x10B,
}

internal enum CommitState : ushort
{
    Unspecified = 0,
    NotCommitted = 1,
    Committed = 2,
    Unknown = 3,
}

internal enum UnlockMode : byte
{
    /// <summary>Passphrase typed into the broker's own masked console prompt.</summary>
    BrokerPrompt = 0,

    /// <summary>Windows Hello (WebAuthn PRF with required UV).</summary>
    HelloPrf = 1,
}

internal enum CopyMode : byte
{
    /// <summary>
    /// Code-capable names (historical case-sensitive "totp" substring or an
    /// exact "topt" alias component — see <see cref="NameCodec.IsCodeName"/>)
    /// copy the code; everything else copies the value.
    /// </summary>
    Auto = 0,
    RawValue = 1,
    Code = 2,
}

internal enum UpdateMode : byte
{
    /// <summary>Replace the value; it is entered in the broker's masked prompt.</summary>
    PromptValue = 0,
    RenameOnly = 1,
    Renew = 2,
}

[Flags]
internal enum BrokerCaps : uint
{
    None = 0,
    Copy = 1,
    Codes = 2,
    Writes = 4,
    Hello = 8,
}

/// <summary>One store entry as metadata only (raw name bytes + slot).</summary>
internal sealed record EntryInfo(ulong Slot, byte[] RawName)
{
    internal string DisplayName => NameCodec.ToDisplayString(RawName);
    internal bool IsCodeName => NameCodec.IsCodeName(RawName);
}

/// <summary>Entry details as metadata only. No value bytes.</summary>
internal sealed record EntryDetail(ulong Slot, byte[] RawName, bool IsCode, uint ValueLength, uint CodeRemainingSeconds);

/// <summary>Outcome of a broker-side clipboard operation. No code or value bytes.</summary>
internal sealed record CopyOutcome(uint ClipboardTtlMs, uint CodeRemainingSeconds, byte Digits);

/// <summary>Outcome of a store mutation. No value bytes.</summary>
/// <remarks>
/// Warning bits (interpreted only when <see cref="Commit"/> is Committed):
/// 0x1 contained panic after the commit checkpoint (write durable, reporting
/// failed); 0x2 cancellation after the commit checkpoint (same meaning);
/// 0x4 writer mutex was abandoned by a dead holder (no integrity claim).
/// </remarks>
internal sealed record WriteOutcome(ulong Slot, uint WarnBits, CommitState Commit, uint ClipboardTtlMs);

internal sealed record HelloInfo(BrokerLifecycle Lifecycle, HelloState Hello, ushort MaxVersion, uint Generation, BrokerCaps Caps);

internal sealed record PingInfo(BrokerLifecycle Lifecycle, HelloState Hello, uint Generation);

internal sealed record HelloStateResult(HelloState Hello);

internal sealed class BrokerRequestException : Exception
{
    internal BrokerRequestException(BrokerStatus status, ushort aux)
        : base(BrokerClient.Describe(status, aux))
    {
        Status = status;
        Aux = aux;
    }

    internal BrokerStatus Status { get; }
    internal ushort Aux { get; }
}

internal sealed class BrokerProtocolException : Exception
{
    internal BrokerProtocolException(string message)
        : base(message)
    {
    }
}

internal sealed class BrokerLaunchException : Exception
{
    internal BrokerLaunchException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

/// <summary>
/// Raw name byte handling. Identity is ALWAYS exact raw bytes (upstream store
/// semantics); the display string is a lossy UTF-8 rendering used only for UI.
/// </summary>
internal static class NameCodec
{
    internal const int MaxNameBytes = 255;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly UTF8Encoding LossyUtf8 = new(false, false);

    internal static string ToDisplayString(byte[] rawName) => LossyUtf8.GetString(rawName);

    /// <summary>Encodes UI text to UTF-8 bytes without name-length rules (search needles).</summary>
    /// <exception cref="ArgumentException">The text is not valid UTF-16 (unpaired surrogates).</exception>
    internal static byte[] Utf8Bytes(string text)
    {
        try
        {
            return StrictUtf8.GetBytes(text);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException("Text contains characters that are not valid UTF-16.", nameof(text), ex);
        }
    }

    /// <summary>Encodes UI text to the raw name bytes that will be stored.</summary>
    /// <exception cref="ArgumentException">The text is not valid UTF-16 (unpaired surrogates).</exception>
    internal static byte[] FromDisplayString(string text)
    {
        byte[] bytes = Utf8Bytes(text);
        if (bytes.Length is 0 or > MaxNameBytes)
        {
            throw new ArgumentException("Name must be 1..255 UTF-8 bytes.", nameof(text));
        }

        return bytes;
    }

    /// <summary>
    /// Code-name candidate for auto-copy labeling. Must agree EXACTLY with
    /// the broker's code routing (wsecret-broker <c>code_candidate</c>): the
    /// historical upstream rule — a name containing the case-SENSITIVE
    /// substring "totp" is a TOTP seed — plus the exact "topt" alias path
    /// component. Case variants ("TOTP") and near-misses ("topt-notes",
    /// "topt32") are NOT code names. The broker's Meta response is
    /// authoritative for whether a code actually derives; this is the
    /// list-view / auto-copy label heuristic.
    /// </summary>
    internal static bool IsCodeName(byte[] rawName)
    {
        ReadOnlySpan<byte> name = rawName;
        return name.IndexOf("totp"u8) >= 0 || HasComponent(rawName, "topt"u8);
    }

    /// <summary>
    /// Codes auto-index membership (docs/quick-access.md §5): an exact,
    /// case-sensitive "/"-separated component "totp", "totp32" or "topt"
    /// (wsecret-core <c>quick::discover_code</c>). This is what enters the
    /// Codes list; <see cref="IsCodeName"/> is the broader auto-copy label
    /// rule and additionally admits the historical substring-only names
    /// (e.g. "mytotpkey"), which support an explicit code request but do
    /// not auto-index.
    /// </summary>
    internal static bool IsAutoIndexedCodeName(byte[] rawName) =>
        HasComponent(rawName, "totp"u8) ||
        HasComponent(rawName, "totp32"u8) ||
        HasComponent(rawName, "topt"u8);

    private static bool HasComponent(byte[] rawName, ReadOnlySpan<byte> component)
    {
        ReadOnlySpan<byte> name = rawName;
        while (true)
        {
            int slash = name.IndexOf((byte)'/');
            if (slash < 0)
            {
                return name.SequenceEqual(component);
            }

            if (name.Slice(0, slash).SequenceEqual(component))
            {
                return true;
            }

            name = name.Slice(slash + 1);
        }
    }
}

/// <summary>Frame codec for broker protocol v1.</summary>
internal static class BrokerWire
{
    internal const uint Magic = 0x31425357; // "WSB1"
    internal const ushort Version = 1;
    internal const int HeaderSize = 24;
    internal const int MaxPayload = 65536;

    internal const ushort OpHello = 0x0001;
    internal const ushort OpPing = 0x0002;
    internal const ushort OpCancel = 0x0003;
    internal const ushort OpShutdown = 0x0004;
    internal const ushort OpUnlock = 0x0010;
    internal const ushort OpLock = 0x0011;
    internal const ushort OpList = 0x0020;
    internal const ushort OpMeta = 0x0021;
    internal const ushort OpCopy = 0x0022;
    internal const ushort OpCode = 0x0023;
    internal const ushort OpCodeTargets = 0x0024;
    internal const ushort OpNew = 0x0030;
    internal const ushort OpSet = 0x0031;
    internal const ushort OpUpdate = 0x0032;
    internal const ushort OpHelloEnroll = 0x0040;
    internal const ushort OpHelloForget = 0x0041;

    internal readonly record struct FrameHeader(ushort Opcode, uint Flags, uint RequestId, uint Generation, uint PayloadLength);

    internal static byte[] BuildRequest(ushort opcode, uint requestId, uint generation, ReadOnlySpan<byte> payload)
    {
        if (requestId == 0)
        {
            throw new ArgumentException("request_id must be nonzero.", nameof(requestId));
        }

        if (payload.Length > MaxPayload)
        {
            throw new ArgumentException("Payload exceeds the protocol bound.", nameof(payload));
        }

        byte[] frame = new byte[HeaderSize + payload.Length];
        Span<byte> span = frame.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(4), Version);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(6), opcode);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(8), 0); // flags MUST be 0
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(12), requestId);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(16), generation);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(20), (uint)payload.Length);
        payload.CopyTo(span.Slice(HeaderSize));
        return frame;
    }

    /// <summary>Validates and parses a response header; throws on any violation.</summary>
    internal static FrameHeader ParseHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length != HeaderSize)
        {
            throw new BrokerProtocolException("Header length mismatch.");
        }

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (magic != Magic)
        {
            throw new BrokerProtocolException("Bad frame magic.");
        }

        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(4));
        if (version != Version)
        {
            throw new BrokerProtocolException("Frame version mismatch.");
        }

        ushort opcode = BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(6));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(8));
        if (flags != 0)
        {
            throw new BrokerProtocolException("Nonzero frame flags.");
        }

        uint requestId = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(12));
        uint generation = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(16));
        uint payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(20));
        if (payloadLength > MaxPayload)
        {
            throw new BrokerProtocolException("Frame payload exceeds the protocol bound.");
        }

        return new FrameHeader(opcode, flags, requestId, generation, payloadLength);
    }
}

/// <summary>Sequential little-endian payload builder.</summary>
internal sealed class PayloadBuilder
{
    private byte[] _buffer = new byte[128];
    private int _length;

    internal PayloadBuilder U8(byte value)
    {
        Ensure(1);
        _buffer[_length++] = value;
        return this;
    }

    internal PayloadBuilder U16(ushort value)
    {
        Ensure(2);
        BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(_length), value);
        _length += 2;
        return this;
    }

    internal PayloadBuilder U32(uint value)
    {
        Ensure(4);
        BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_length), value);
        _length += 4;
        return this;
    }

    internal PayloadBuilder U64(ulong value)
    {
        Ensure(8);
        BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_length), value);
        _length += 8;
        return this;
    }

    internal PayloadBuilder Pad(int count)
    {
        Ensure(count);
        _buffer.AsSpan(_length, count).Clear();
        _length += count;
        return this;
    }

    /// <summary>Length-prefixed raw name bytes (u16 length, ≤255).</summary>
    internal PayloadBuilder Name(ReadOnlySpan<byte> rawName)
    {
        if (rawName.Length is 0 or > NameCodec.MaxNameBytes)
        {
            throw new ArgumentException("Name must be 1..255 bytes.", nameof(rawName));
        }

        U16((ushort)rawName.Length);
        return Raw(rawName);
    }

    internal PayloadBuilder Raw(ReadOnlySpan<byte> data)
    {
        Ensure(data.Length);
        data.CopyTo(_buffer.AsSpan(_length));
        _length += data.Length;
        return this;
    }

    internal ReadOnlySpan<byte> AsSpan() => _buffer.AsSpan(0, _length);

    private void Ensure(int extra)
    {
        if (_length + extra <= _buffer.Length)
        {
            return;
        }

        int newSize = Math.Max(_buffer.Length * 2, _length + extra);
        Array.Resize(ref _buffer, newSize);
    }
}

/// <summary>Sequential little-endian payload reader with strict bounds.</summary>
internal ref struct PayloadReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _position;

    internal PayloadReader(ReadOnlySpan<byte> data) => _data = data;

    internal int Remaining => _data.Length - _position;

    internal byte U8()
    {
        Require(1);
        return _data[_position++];
    }

    internal ushort U16()
    {
        Require(2);
        ushort value = BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_position));
        _position += 2;
        return value;
    }

    internal uint U32()
    {
        Require(4);
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_position));
        _position += 4;
        return value;
    }

    internal ulong U64()
    {
        Require(8);
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_position));
        _position += 8;
        return value;
    }

    internal void Skip(int count)
    {
        Require(count);
        _position += count;
    }

    /// <summary>Reads a length-prefixed raw name (u16 length, ≤255).</summary>
    internal byte[] Name()
    {
        int length = U16();
        if (length is 0 or > NameCodec.MaxNameBytes)
        {
            throw new BrokerProtocolException("Name length outside protocol bounds.");
        }

        Require(length);
        byte[] name = _data.Slice(_position, length).ToArray();
        _position += length;
        return name;
    }

    /// <summary>
    /// Verifies the response payload was consumed exactly (strict codec rule:
    /// trailing bytes or short payload is a protocol violation).
    /// </summary>
    internal void RequireEnd()
    {
        if (Remaining != 0)
        {
            throw new BrokerProtocolException("Trailing bytes in response payload.");
        }
    }

    private void Require(int count)
    {
        if (count > Remaining)
        {
            throw new BrokerProtocolException("Truncated response payload.");
        }
    }
}

/// <summary>
/// Client of the wsecret-broker process over a private inherited anonymous
/// pipe pair (no named endpoint). Carries metadata only: the broker owns every
/// secret, the sessions, the masked prompts, the secure clipboard and Hello.
///
/// Stale-response rejection: every request records the generation it was sent
/// under; a response is delivered only when its request id is still
/// outstanding AND its generation equals the client's last known generation.
/// Anything else is dropped without being parsed by callers.
/// </summary>
internal sealed class BrokerClient : IAsyncDisposable
{
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(130);
    private const int MaxPagedEntries = 10_000;

    /// <summary>Broker-side <c>protocol::MAX_CODE_TARGETS</c> (defensive bound).</summary>
    private const int MaxCodeTargets = 64;

    private readonly FileStream _toBroker;
    private readonly FileStream _fromBroker;
    private readonly SafeFileHandle _brokerProcessHandle;
    private readonly int _processId;
    private readonly object _writeLock = new();
    private readonly ConcurrentDictionary<uint, PendingRequest> _pending = new();
    private readonly Thread _readerThread;
    private readonly CancellationTokenSource _lifetime = new();
    private int _nextRequestId;
    private uint _generation;
    private int _closed;
    internal event Action? Disconnected;

    private BrokerClient(FileStream toBroker, FileStream fromBroker, SafeFileHandle processHandle, int processId)
    {
        _toBroker = toBroker;
        _fromBroker = fromBroker;
        _brokerProcessHandle = processHandle;
        _processId = processId;
        _generation = 0;
        _readerThread = new Thread(ReaderLoop)
        {
            IsBackground = true,
            Name = "wsecret-broker-reader",
        };
        _readerThread.Start();
    }

    internal int ProcessId => _processId;

    /// <summary>Last known session generation (broker-owned counter).</summary>
    internal uint Generation => Volatile.Read(ref _generation);

    private sealed class PendingRequest
    {
        internal PendingRequest(uint requestId, ushort opcode, uint generation)
        {
            RequestId = requestId;
            Opcode = opcode;
            Generation = generation;
        }

        internal uint RequestId { get; }
        internal ushort Opcode { get; }
        internal uint Generation { get; }
        internal TaskCompletionSource<byte[]> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    // ---- lifecycle -------------------------------------------------------

    /// <summary>
    /// Spawns wsecret-broker.exe with exactly two inherited pipe handles and
    /// performs the Hello handshake. Throws <see cref="BrokerLaunchException"/>
    /// with a user-presentable message on any failure.
    /// </summary>
    internal static async Task<BrokerClient> StartAsync(string brokerExePath, string? storePath, CancellationToken cancellationToken)
    {
        if (!File.Exists(brokerExePath))
        {
            throw new BrokerLaunchException($"Broker executable not found: {brokerExePath}");
        }

        // Command pipe: parent writes, broker reads. Response pipe: broker
        // writes, parent reads. Broker ends inheritable; parent ends not.
        Native.SECURITY_ATTRIBUTES inheritable = new() { nLength = Marshal.SizeOf<Native.SECURITY_ATTRIBUTES>(), bInheritHandle = 1 };
        Native.SECURITY_ATTRIBUTES attributes = inheritable;
        if (!Native.CreatePipe(out IntPtr brokerCmdRead, out IntPtr parentCmdWrite, ref attributes, 0))
        {
            throw new BrokerLaunchException("CreatePipe (command) failed.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }

        if (!Native.CreatePipe(out IntPtr parentRespRead, out IntPtr brokerRespWrite, ref attributes, 0))
        {
            Native.CloseHandle(brokerCmdRead);
            Native.CloseHandle(parentCmdWrite);
            throw new BrokerLaunchException("CreatePipe (response) failed.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }

        // Parent ends must not leak into the broker (or its future children).
        Native.SetHandleInformation(parentCmdWrite, Native.HANDLE_FLAG_INHERIT, 0);
        Native.SetHandleInformation(parentRespRead, Native.HANDLE_FLAG_INHERIT, 0);

        var arguments = new List<string>
        {
            "--rd-handle", brokerCmdRead.ToInt64().ToString(),
            "--wr-handle", brokerRespWrite.ToInt64().ToString(),
        };
        if (!string.IsNullOrEmpty(storePath))
        {
            arguments.Add("--store");
            arguments.Add(storePath);
        }

        IntPtr hProcess;
        int processId;
        try
        {
            Native.LaunchBrokerWithInheritedHandles(brokerExePath, arguments, new[] { brokerCmdRead, brokerRespWrite }, out hProcess, out processId);
        }
        catch (Exception ex)
        {
            // Broker ends are closed in the finally below exactly once.
            Native.CloseHandle(parentCmdWrite);
            Native.CloseHandle(parentRespRead);
            throw new BrokerLaunchException("Failed to start wsecret-broker.exe.", ex);
        }
        finally
        {
            // The parent must drop its copies of the broker ends so pipe EOF
            // reflects exactly the broker's lifetime.
            Native.CloseHandle(brokerCmdRead);
            Native.CloseHandle(brokerRespWrite);
        }

        var toBroker = new FileStream(new SafeFileHandle(parentCmdWrite, ownsHandle: true), FileAccess.Write, 4096, isAsync: false);
        var fromBroker = new FileStream(new SafeFileHandle(parentRespRead, ownsHandle: true), FileAccess.Read, 4096, isAsync: false);
        var processHandle = new SafeFileHandle(hProcess, ownsHandle: true);

        var client = new BrokerClient(toBroker, fromBroker, processHandle, processId);
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(HandshakeTimeout);
            await client.HelloAsync(handshakeCts.Token).ConfigureAwait(false);
            return client;
        }
        catch (Exception ex)
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw new BrokerLaunchException(
                "Broker handshake failed: " + DescribeLaunchFailure(processHandle, ex),
                ex);
        }
    }

    private static string DescribeLaunchFailure(SafeFileHandle processHandle, Exception ex)
    {
        if (Native.GetExitCodeProcess(processHandle.DangerousGetHandle(), out int exitCode) && exitCode is >= 2 and <= 5)
        {
            string reason = exitCode switch
            {
                2 => "the broker rejected its launch arguments",
                3 => "the broker's protection initialization failed",
                4 => "the broker rejected the inherited channel handles",
                5 => "the handshake failed inside the broker",
                _ => "unknown broker startup failure",
            };
            return $"{reason} (exit code {exitCode}).";
        }

        return ex.Message;
    }

    // ---- operations ------------------------------------------------------

    internal async Task<HelloInfo> HelloAsync(CancellationToken cancellationToken)
    {
        byte[] payload = await RequestAsync(BrokerWire.OpHello, new PayloadBuilder(), cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        var info = new HelloInfo(
            (BrokerLifecycle)reader.U8(),
            (HelloState)reader.U8(),
            reader.U16(),
            reader.U32(),
            (BrokerCaps)reader.U32());
        reader.RequireEnd();
        return info;
    }

    internal async Task<PingInfo> PingAsync(CancellationToken cancellationToken)
    {
        byte[] payload = await RequestAsync(BrokerWire.OpPing, new PayloadBuilder(), cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        BrokerLifecycle lifecycle = (BrokerLifecycle)reader.U8();
        HelloState hello = (HelloState)reader.U8();
        reader.Skip(2); // pad
        uint generation = reader.U32();
        reader.RequireEnd();
        var info = new PingInfo(lifecycle, hello, generation);
        return info;
    }

    /// <summary>Unlocks a session; the completion moves the generation.</summary>
    internal async Task<uint> UnlockAsync(UnlockMode mode, CancellationToken cancellationToken)
    {
        var builder = new PayloadBuilder().U8((byte)mode).Pad(3);
        byte[] payload = await RequestAsync(BrokerWire.OpUnlock, builder, cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        uint newGeneration = reader.U32();
        reader.RequireEnd();
        return newGeneration;
    }

    /// <summary>Locks the session; the completion moves the generation.</summary>
    internal async Task<uint> LockAsync(bool clearClipboard, CancellationToken cancellationToken)
    {
        var builder = new PayloadBuilder().U8(clearClipboard ? (byte)1 : (byte)0);
        byte[] payload = await RequestAsync(BrokerWire.OpLock, builder, cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        uint newGeneration = reader.U32();
        reader.RequireEnd();
        return newGeneration;
    }

    internal async Task<(uint Total, List<EntryInfo> Entries)> ListAsync(uint offset, ushort count, byte[] needle, CancellationToken cancellationToken)
    {
        if (count is 0 or > 240)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Page size must be 1..240.");
        }

        if (needle.Length > NameCodec.MaxNameBytes)
        {
            throw new ArgumentException("Needle exceeds 255 bytes.", nameof(needle));
        }

        var builder = new PayloadBuilder().U32(offset).U16(count).U16((ushort)needle.Length).Raw(needle);
        byte[] payload = await RequestAsync(BrokerWire.OpList, builder, cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        uint total = reader.U32();
        ushort returned = reader.U16();
        reader.Skip(2); // pad
        var entries = new List<EntryInfo>(returned);
        for (int i = 0; i < returned; i++)
        {
            ulong slot = reader.U64();
            byte[] name = reader.Name();
            entries.Add(new EntryInfo(slot, name));
        }

        reader.RequireEnd();
        return (total, entries);
    }

    /// <summary>Pages through the whole list (bounded) in one logical call.</summary>
    internal async Task<(uint Total, List<EntryInfo> Entries)> ListAllAsync(byte[] needle, CancellationToken cancellationToken)
    {
        var all = new List<EntryInfo>();
        uint total = 0;
        uint offset = 0;
        while (true)
        {
            (total, List<EntryInfo> page) = await ListAsync(offset, 240, needle, cancellationToken).ConfigureAwait(false);
            all.AddRange(page);
            offset += (uint)page.Count;
            if (page.Count == 0 || offset >= total || all.Count >= MaxPagedEntries)
            {
                break;
            }
        }

        return (total, all);
    }

    internal async Task<EntryDetail> MetaAsync(byte[] name, CancellationToken cancellationToken)
    {
        var builder = new PayloadBuilder().Name(name);
        byte[] payload = await RequestAsync(BrokerWire.OpMeta, builder, cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        ulong slot = reader.U64();
        byte kind = reader.U8();
        reader.Skip(3); // pad3
        uint valueLength = reader.U32();
        uint codeRemaining = reader.U32();
        byte[] echo = reader.Name();
        reader.RequireEnd();
        return new EntryDetail(slot, echo, kind == 1, valueLength, codeRemaining);
    }

    /// <summary>
    /// Checked copy: the broker requires the unique record carrying
    /// <paramref name="entry"/>'s exact name to still live at its slot.
    /// Deleted, renamed/moved/recreated-elsewhere and duplicate-named records
    /// refuse with <see cref="BrokerStatus.NotFound"/> /
    /// <see cref="BrokerStatus.Conflict"/>; a newer value at the same
    /// slot + name is current and is what gets copied (upstream semantics).
    /// </summary>
    internal async Task<CopyOutcome> CopyAsync(EntryInfo entry, CopyMode mode, CancellationToken cancellationToken)
    {
        var builder = new PayloadBuilder().Name(entry.RawName).U8((byte)mode).Pad(3).U64(entry.Slot);

        byte[] payload = await RequestAsync(BrokerWire.OpCopy, builder, cancellationToken).ConfigureAwait(false);
        return ReadCopyOutcome(payload);
    }

    /// <summary>
    /// Checked code copy: the same identity guard as
    /// <see cref="CopyAsync(EntryInfo, CopyMode, CancellationToken)"/>.
    /// </summary>
    internal async Task<CopyOutcome> CodeAsync(EntryInfo entry, CancellationToken cancellationToken)
    {
        var builder = new PayloadBuilder().Name(entry.RawName).U64(entry.Slot);

        byte[] payload = await RequestAsync(BrokerWire.OpCode, builder, cancellationToken).ConfigureAwait(false);
        return ReadCodeOutcome(payload);
    }

    private static CopyOutcome ReadCopyOutcome(byte[] payload)
    {
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        uint clipboardTtl = reader.U32();
        uint codeRemaining = reader.U32();
        byte digits = reader.U8();
        reader.Skip(3); // pad3
        reader.RequireEnd();
        return new CopyOutcome(clipboardTtl, codeRemaining, digits);
    }

    private static CopyOutcome ReadCodeOutcome(byte[] payload)
    {
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        uint codeRemaining = reader.U32();
        uint clipboardTtl = reader.U32();
        byte digits = reader.U8();
        reader.Skip(3); // pad3
        reader.RequireEnd();
        return new CopyOutcome(clipboardTtl, codeRemaining, digits);
    }

    /// <summary>
    /// The exact safe code records for one picked item (the Ctrl+Enter
    /// "Copy code" chooser input), metadata only: the item itself when it is
    /// code-capable, otherwise exactly the records the core link rule
    /// attaches to this record in this partition — never a descendant guess,
    /// never cross-vault. Fails closed with
    /// <see cref="BrokerRequestException"/> on a stale/moved selection,
    /// ambiguous (duplicate) names, a partial index or an oversized result;
    /// an EMPTY list is the "no linked code" answer. Call on user copy
    /// intent only — every call scans the session once.
    /// </summary>
    internal async Task<List<EntryInfo>> CodeTargetsAsync(EntryInfo entry, CancellationToken cancellationToken)
    {
        var builder = new PayloadBuilder().U64(entry.Slot).Name(entry.RawName);
        byte[] payload = await RequestAsync(BrokerWire.OpCodeTargets, builder, cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        ushort count = reader.U16();
        reader.Skip(2); // pad
        if (count > MaxCodeTargets)
        {
            throw new BrokerProtocolException("Code target count outside protocol bounds.");
        }

        var targets = new List<EntryInfo>(count);
        for (int i = 0; i < count; i++)
        {
            ulong slot = reader.U64();
            byte[] name = reader.Name();
            targets.Add(new EntryInfo(slot, name));
        }

        reader.RequireEnd();
        return targets;
    }

    /// <summary>Generates and stores a new entry (random or deterministic).</summary>
    /// <remarks>
    /// Wire preconditions (violations are fatal protocol errors): gen=1
    /// (deterministic) requires at least one component; gen=0 (random)
    /// requires exactly zero components.
    /// </remarks>
    internal async Task<WriteOutcome> NewAsync(byte[] name, bool deterministic, IReadOnlyList<byte[]> subkeys, CancellationToken cancellationToken)
    {
        if (deterministic && subkeys.Count == 0)
        {
            throw new ArgumentException("Deterministic generation requires at least one component (upstream pass semantics).", nameof(subkeys));
        }

        if (!deterministic && subkeys.Count != 0)
        {
            throw new ArgumentException("Random generation takes no components.", nameof(subkeys));
        }

        var builder = new PayloadBuilder().Name(name).U8(deterministic ? (byte)1 : (byte)0).Pad(1);
        if (deterministic)
        {
            if (subkeys.Count > ushort.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(subkeys));
            }

            builder.U16((ushort)subkeys.Count);
            foreach (byte[] subkey in subkeys)
            {
                // Upstream s_keylen rule: 1..=255 raw UTF-8 bytes, no byte ≤ 0x20.
                if (subkey.Length is 0 or > NameCodec.MaxNameBytes)
                {
                    throw new ArgumentException("Each component must be 1..255 bytes.", nameof(subkeys));
                }

                foreach (byte b in subkey)
                {
                    if (b <= 0x20)
                    {
                        throw new ArgumentException("Components must not contain bytes <= 0x20 (upstream keylen rule).", nameof(subkeys));
                    }
                }

                builder.U16((ushort)subkey.Length).Raw(subkey);
            }
        }
        else
        {
            builder.U16(0);
        }

        byte[] payload = await RequestAsync(BrokerWire.OpNew, builder, cancellationToken).ConfigureAwait(false);
        return ReadWriteOutcome(payload);
    }

    /// <summary>Creates/replace an entry with a value entered in the broker's masked prompt.</summary>
    internal async Task<WriteOutcome> SetAsync(byte[] name, CancellationToken cancellationToken)
    {
        var builder = new PayloadBuilder().Name(name);
        byte[] payload = await RequestAsync(BrokerWire.OpSet, builder, cancellationToken).ConfigureAwait(false);
        return ReadWriteOutcome(payload);
    }

    /// <summary>
    /// Updates an entry. <paramref name="expectSlot"/> is the compare-and-swap
    /// guard: 0 disables it; a nonzero slot that no longer matches the record
    /// found for <paramref name="name"/> fails with <see cref="BrokerStatus.Conflict"/>.
    /// Rename-only mode requires a nonempty new name (wire precondition).
    /// </summary>
    internal async Task<WriteOutcome> UpdateAsync(ulong expectSlot, byte[] name, byte[]? newName, UpdateMode mode, CancellationToken cancellationToken)
    {
        if (mode == UpdateMode.RenameOnly && (newName is null || newName.Length == 0))
        {
            throw new ArgumentException("Rename-only updates require a nonempty new name.", nameof(newName));
        }

        var builder = new PayloadBuilder().U64(expectSlot).Name(name);
        if (newName is null)
        {
            builder.U16(0);
        }
        else
        {
            builder.Name(newName);
        }

        builder.U8((byte)mode);
        byte[] payload = await RequestAsync(BrokerWire.OpUpdate, builder, cancellationToken).ConfigureAwait(false);
        return ReadWriteOutcome(payload);
    }

    internal async Task<HelloStateResult> HelloEnrollAsync(CancellationToken cancellationToken)
    {
        byte[] payload = await RequestAsync(BrokerWire.OpHelloEnroll, new PayloadBuilder(), cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        var result = new HelloStateResult((HelloState)reader.U8());
        reader.RequireEnd();
        return result;
    }

    internal async Task<HelloStateResult> HelloForgetAsync(CancellationToken cancellationToken)
    {
        byte[] payload = await RequestAsync(BrokerWire.OpHelloForget, new PayloadBuilder(), cancellationToken).ConfigureAwait(false);
        PayloadReader reader = new(payload);
        ReadStatus(ref reader);
        var result = new HelloStateResult((HelloState)reader.U8());
        reader.RequireEnd();
        return result;
    }

    /// <summary>Requests a clean broker teardown (lock + wipe + clipboard clear).</summary>
    internal async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        try
        {
            byte[] payload = await RequestAsync(BrokerWire.OpShutdown, new PayloadBuilder(), cancellationToken).ConfigureAwait(false);
            PayloadReader reader = new(payload);
            ReadStatus(ref reader);
        }
        catch (Exception)
        {
            // Teardown is best effort: disposal closes the pipes and the
            // broker treats EOF as a lock+wipe+exit signal.
        }
    }

    // ---- plumbing --------------------------------------------------------

    private static WriteOutcome ReadWriteOutcome(byte[] payload)
    {
        PayloadReader reader = new(payload);
        ushort aux = ReadStatus(ref reader);
        ulong slot = reader.U64();
        uint warnBits = reader.U32();
        uint clipboardTtl = reader.U32();
        reader.RequireEnd();
        return new WriteOutcome(slot, warnBits, (CommitState)aux, clipboardTtl);
    }

    private static ushort ReadStatus(ref PayloadReader reader)
    {
        var status = (BrokerStatus)reader.U16();
        ushort aux = reader.U16();
        if (status != BrokerStatus.Ok)
        {
            throw new BrokerRequestException(status, aux);
        }

        return aux;
    }

    private uint NextRequestId()
    {
        // request_id 0 is reserved/rejected by the broker.
        uint id = (uint)Interlocked.Increment(ref _nextRequestId);
        return id == 0 ? (uint)Interlocked.Increment(ref _nextRequestId) : id;
    }

    private async Task<byte[]> RequestAsync(ushort opcode, PayloadBuilder payload, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _closed) != 0, this);

        uint requestId = NextRequestId();
        uint generation = Generation;
        var pending = new PendingRequest(requestId, opcode, generation);
        if (!_pending.TryAdd(requestId, pending))
        {
            throw new BrokerProtocolException("Request id collision.");
        }

        byte[] frame = BrokerWire.BuildRequest(opcode, requestId, generation, payload.AsSpan());
        lock (_writeLock)
        {
            _toBroker.Write(frame, 0, frame.Length);
            _toBroker.Flush();
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        timeoutCts.CancelAfter(RequestTimeout);
        await using CancellationTokenRegistration registration = timeoutCts.Token.Register(() =>
        {
            if (_pending.TryRemove(requestId, out PendingRequest? stale))
            {
                if (opcode is BrokerWire.OpUnlock or BrokerWire.OpLock)
                {
                    // A lifecycle response can advance generation after this
                    // timeout. Do not leave the channel permanently unable to
                    // accept Ping or later lifecycle responses: close it and
                    // require an explicit reconnect instead.
                    try
                    {
                        _toBroker.Dispose();
                        _fromBroker.Dispose();
                    }
                    catch (Exception)
                    {
                    }
                    _lifetime.Cancel();
                    FailAllPending();
                }
                else
                {
                    SendCancelBestEffort(requestId);
                }
                stale.Completion.TrySetCanceled(timeoutCts.Token);
            }
        });

        try
        {
            return await pending.Completion.Task.ConfigureAwait(false);
        }
        finally
        {
            _pending.TryRemove(requestId, out _);
        }
    }

    private void SendCancelBestEffort(uint targetRequestId)
    {
        try
        {
            byte[] frame = BrokerWire.BuildRequest(
                BrokerWire.OpCancel,
                NextRequestId(),
                Generation,
                new PayloadBuilder().U32(targetRequestId).AsSpan());
            lock (_writeLock)
            {
                _toBroker.Write(frame, 0, frame.Length);
                _toBroker.Flush();
            }
        }
        catch (Exception)
        {
            // Best effort only.
        }
    }

    private void ReaderLoop()
    {
        byte[] headerBuffer = new byte[BrokerWire.HeaderSize];
        try
        {
            while (_lifetime.IsCancellationRequested == false)
            {
                if (!TryReadExactly(_fromBroker, headerBuffer))
                {
                    break; // EOF: broker teardown.
                }

                BrokerWire.FrameHeader header = BrokerWire.ParseHeader(headerBuffer);
                byte[] payload = new byte[header.PayloadLength];
                if (payload.Length > 0 && !TryReadExactly(_fromBroker, payload))
                {
                    break;
                }

                DeliverFrame(header, payload);
            }
        }
        catch (Exception)
        {
            // Protocol violation or I/O failure: fall through to teardown.
        }
        finally
        {
            if (Volatile.Read(ref _closed) == 0) Disconnected?.Invoke();
            FailAllPending();
        }
    }

    private void DeliverFrame(in BrokerWire.FrameHeader header, byte[] payload)
    {
        if (!_pending.TryGetValue(header.RequestId, out PendingRequest? pending))
        {
            return;
        }

        uint generation = Generation;
        bool lifecycleAdvance = pending.Opcode is BrokerWire.OpUnlock or BrokerWire.OpLock
            && pending.Generation == generation
            && header.Generation == unchecked(pending.Generation + 1);
        bool currentEpoch = pending.Generation == generation && header.Generation == generation;
        if (!currentEpoch && !lifecycleAdvance)
        {
            return;
        }

        // Unlock and lock complete the old epoch and atomically establish the
        // next one, including on an error response. Accept exactly +1 for the
        // outstanding lifecycle operation; every other response must belong
        // to the client's current epoch.
        if (lifecycleAdvance
            && Interlocked.CompareExchange(ref _generation, header.Generation, generation) != generation)
        {
            return;
        }

        if (!_pending.TryRemove(header.RequestId, out PendingRequest? removed)
            || !ReferenceEquals(removed, pending))
        {
            return;
        }

        pending.Completion.TrySetResult(payload);
    }

    private static bool TryReadExactly(Stream stream, byte[] buffer)
    {
        int filled = 0;
        while (filled < buffer.Length)
        {
            int read = stream.Read(buffer, filled, buffer.Length - filled);
            if (read <= 0)
            {
                return false;
            }

            filled += read;
        }

        return true;
    }

    private void FailAllPending()
    {
        Native.WaitForSingleObject(_brokerProcessHandle.DangerousGetHandle(), 1000);
        string detail = Native.GetExitCodeProcess(_brokerProcessHandle.DangerousGetHandle(), out int exitCode)
            ? $" Broker exit code 0x{exitCode:X8}."
            : " Broker exit code unavailable.";
        foreach (uint requestId in _pending.Keys)
        {
            if (_pending.TryRemove(requestId, out PendingRequest? pending))
            {
                pending.Completion.TrySetException(new IOException("Broker channel closed." + detail));
            }
        }
    }

    internal static string Describe(BrokerStatus status, ushort aux) =>
        status switch
        {
            BrokerStatus.Ok => "OK",
            BrokerStatus.InvalidArgument => "The broker rejected the request as malformed and terminated the channel.",
            BrokerStatus.InvalidName => "The name is invalid (upstream name rules).",
            BrokerStatus.EntryTooBig => "The entry exceeds the store's size limits.",
            BrokerStatus.StoreNotFound => "The store file was not found.",
            BrokerStatus.UnsupportedVersion => "The store format version is not supported.",
            BrokerStatus.MalformedStore => "The store file is malformed.",
            BrokerStatus.ResourceLimit => "A configured resource limit was exceeded (KDF cost or index bounds).",
            BrokerStatus.NotFound => "No such entry.",
            BrokerStatus.AlreadyExists => "That entry already exists.",
            BrokerStatus.PassphraseMismatch => "The passphrase confirmation did not match; nothing was unlocked.",
            BrokerStatus.Locked => "The vault is locked.",
            BrokerStatus.Conflict => "The record changed or its name is ambiguous (more than one entry has it); nothing was copied or written.",
            BrokerStatus.Cancelled => "The request was cancelled.",
            BrokerStatus.Io => "Store I/O error.",
            BrokerStatus.Crypto => "Cryptographic operation failed.",
            BrokerStatus.NoMemory => "The broker could not allocate protected memory.",
            BrokerStatus.MemoryProtection => "The broker could not protect its secret memory.",
            BrokerStatus.Panic => "The broker contained an internal panic.",
            BrokerStatus.CommitUncertain => "The commit outcome is uncertain; refresh before retrying.",
            BrokerStatus.InvalidTotp => "The stored TOTP seed is invalid.",
            BrokerStatus.VersionMismatch => $"Protocol version mismatch (broker max version {aux}).",
            BrokerStatus.WrongState => "The request is not valid in the current lifecycle state.",
            BrokerStatus.StaleGeneration => "The response was rejected as stale (session generation changed).",
            BrokerStatus.Busy => "The broker is busy with a lifecycle transition or another request.",
            BrokerStatus.Timeout => "The broker timed out the request.",
            BrokerStatus.HelloUnavailable => "Windows Hello (PRF) is unavailable and fail-disabled.",
            BrokerStatus.HelloNotEnrolled => "Windows Hello is not enrolled for this store.",
            BrokerStatus.HelloFailed => "Windows Hello verification failed.",
            BrokerStatus.ClipboardError => "The broker could not place the data on the secure clipboard.",
            BrokerStatus.ValueNotText => "This value is binary; copy was refused.",
            BrokerStatus.NoConsole => aux == 0
                ? "The broker could not create its secure masked prompt."
                : $"The broker could not create its secure masked prompt (Win32 error {aux}).",
            BrokerStatus.InputInvalid => "The input typed at the broker's prompt was rejected (too long, control characters, or invalid text).",
            _ => $"Broker status 0x{(int)status:X}.",
        };

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await ShutdownAsync(shutdownCts.Token).ConfigureAwait(false);

        _lifetime.Cancel();
        try
        {
            _toBroker.Dispose();
        }
        catch (Exception)
        {
        }

        try
        {
            _fromBroker.Dispose();
        }
        catch (Exception)
        {
        }

        // Pipe EOF already tells the broker to lock, wipe and exit. Only a
        // hung broker is terminated, and only after a grace period.
        if (Native.WaitForSingleObject(_brokerProcessHandle.DangerousGetHandle(), 5000) != Native.WAIT_OBJECT_0)
        {
            Native.TerminateProcess(_brokerProcessHandle.DangerousGetHandle(), 1);
        }

        _brokerProcessHandle.Dispose();
        _lifetime.Dispose();
    }
}
