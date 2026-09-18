namespace KeyGuard_SQAProject
{
    internal sealed class Finding
    {
        public long LineNumber { get; init; }
        public string PatternName { get; init; }
        public string RawMatch { get; init; }
        // The file path where the finding was observed. Optional for single-file scans.
        public string FilePath { get; init; } = string.Empty;
        public string Masked => Masking.Mask(RawMatch);
        public override string ToString() => string.IsNullOrEmpty(FilePath)
            ? $"[{LineNumber}] {PatternName}: {Masked}"
            : $"[{FilePath}] [{LineNumber}] {PatternName}: {Masked}";
    }
}