namespace KeyGuard_SQAProject
{
    internal sealed class Finding
    {
        public long LineNumber { get; init; }
        public string PatternName { get; init; }
        public string RawMatch { get; init; }
        public string Masked => Masking.Mask(RawMatch);
        public override string ToString() => $"[{LineNumber}] {PatternName}: {Masked}";
    }
}