namespace KeyGuard_SQAProject
{
    internal static class Luhn
    {
        public static bool IsValid(string digits)
        {
            if (string.IsNullOrEmpty(digits)) return false;
            int sum = 0;
            bool alternate = false;
            for (int i = digits.Length - 1; i >= 0; i--)
            {
                if (digits[i] < '0' || digits[i] > '9') return false;
                int n = digits[i] - '0';
                if (alternate)
                {
                    n *= 2;
                    if (n > 9) n -= 9;
                }
                sum += n;
                alternate = !alternate;
            }
            return (sum % 10) == 0;
        }
    }
}