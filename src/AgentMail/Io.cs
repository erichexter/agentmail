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
}
