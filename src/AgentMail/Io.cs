namespace AgentMail;

static class Io
{
    /// <summary>
    /// Write <paramref name="content"/> to <paramref name="finalPath"/> atomically: write a
    /// sibling ".tmp" file, then move it into place. Readers that glob for the final extension
    /// never observe a partial file. The temp lives in the same directory to keep the move atomic.
    /// </summary>
    public static void WriteAtomic(string finalPath, string content)
    {
        string dir = Path.GetDirectoryName(finalPath)!;
        Directory.CreateDirectory(dir);
        string tmp = finalPath + ".tmp";
        File.WriteAllText(tmp, content);
        File.Move(tmp, finalPath, overwrite: true);
    }

    /// <summary>
    /// Atomic write that fsyncs to disk before the rename. The consume transaction (FLAG-30) needs plaintext
    /// and .done DURABLE before the inbox file is removed: a crash between "wrote .done" and "it reached disk"
    /// would let the message redeliver, or leave .done claiming a consume that did not survive. fsync closes it.
    /// </summary>
    public static void WriteAtomicFsync(string finalPath, string content)
    {
        string dir = Path.GetDirectoryName(finalPath)!;
        Directory.CreateDirectory(dir);
        string tmp = finalPath + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(content);
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(flushToDisk: true);   // fsync
        }
        File.Move(tmp, finalPath, overwrite: true);
    }
}
