// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// This file is a C# port of the binary-to-decimal floating-point conversion routines from the
// Go programming language's strconv package at tag go1.26.0. It combines:
//   * src/internal/strconv/ftoadbox.go  - shortest conversion using the Dragonbox algorithm
//   * src/internal/strconv/ftoafixed.go - bounded (1..18 significant digits) conversion
//   * src/internal/strconv/math.go      - shared 128-bit math helpers
//
// Those Go sources are licensed under a BSD-style license (the 3-clause BSD license used by the
// Go project). See THIRD-PARTY-NOTICES.TXT ("License notice for The Go Programming Language") for
// the full text and https://github.com/golang/go/blob/go1.26.0/LICENSE.
//
// The Dragonbox algorithm itself was designed by Junekey Jeon. The reference C++ implementation is
// NOT used here (only the independently-licensed Go derivative is ported), so Dragonbox's own dual
// license does not apply to this implementation. Algorithm/section references in the comments below
// point at Jeon's paper: https://github.com/jk-jeon/dragonbox/blob/master/other_files/Dragonbox.pdf

using System.Buffers.Text;
using System.Diagnostics;
using System.Numerics;

namespace System
{
    internal static partial class Number
    {
        internal static partial class Dragonbox
        {
            // float64 has p = 52 trailing significand bits, float32 has p = 23.
            private const int Float64MantBits = 52;
            private const int Float32MantBits = 23;

            /// <summary>
            /// Attempts to convert a finite, non-zero <paramref name="value"/> into its decimal digit
            /// representation using the Dragonbox (shortest) or bounded fixed-precision algorithms.
            /// </summary>
            /// <remarks>
            /// Supported requests are <paramref name="requestedDigits"/> == -1 (shortest round-trippable
            /// representation) and 1..18 significant digits. Any other request, as well as <see cref="Half"/>
            /// and <c>BFloat16</c>, returns <see langword="false"/> so the caller can fall back to Dragon4.
            /// </remarks>
            public static bool TryRun<TNumber>(TNumber value, int requestedDigits, ref NumberBuffer number)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                TNumber v = TNumber.IsNegative(value) ? -value : value;

                Debug.Assert(v > TNumber.Zero);
                Debug.Assert(TNumber.IsFinite(v));

                if ((requestedDigits < -1) || (requestedDigits == 0) || (requestedDigits > 18))
                {
                    // Unsupported precision (including >18 significant digits): defer to Dragon4.
                    return false;
                }

                if (typeof(TNumber) == typeof(double))
                {
                    ulong bits = TNumber.FloatToBits(v);
                    int rawExponent = (int)(bits >> Float64MantBits) & 0x7FF;
                    ulong mantissa = bits & ((1UL << Float64MantBits) - 1);
                    bool denormal = false;

                    if (rawExponent == 0)
                    {
                        rawExponent = 1;
                        denormal = true;
                    }
                    else
                    {
                        mantissa |= 1UL << Float64MantBits;
                    }

                    // value == mantissa * 2^exponent
                    int exponent = rawExponent - 1023 - Float64MantBits;

                    if (requestedDigits == -1)
                    {
                        DboxFtoa64(ref number, mantissa, exponent, denormal);
                    }
                    else
                    {
                        FixedFtoa(ref number, mantissa, exponent, requestedDigits);
                    }
                }
                else if (typeof(TNumber) == typeof(float))
                {
                    uint bits = (uint)TNumber.FloatToBits(v);
                    int rawExponent = (int)(bits >> Float32MantBits) & 0xFF;
                    uint mantissa = bits & ((1u << Float32MantBits) - 1);
                    bool denormal = false;

                    if (rawExponent == 0)
                    {
                        rawExponent = 1;
                        denormal = true;
                    }
                    else
                    {
                        mantissa |= 1u << Float32MantBits;
                    }

                    int exponent = rawExponent - 127 - Float32MantBits;

                    if (requestedDigits == -1)
                    {
                        DboxFtoa32(ref number, mantissa, exponent, denormal);
                    }
                    else
                    {
                        // The bounded conversion is bit-size agnostic; Go reuses the same routine.
                        FixedFtoa(ref number, mantissa, exponent, requestedDigits);
                    }
                }
                else
                {
                    // Half and BFloat16 do not have native Dragonbox support here; use Dragon4 instead.
                    return false;
                }

                number.CheckConsistency();
                return true;
            }

            // ftoadbox.go: dboxFtoa64 - shortest conversion for float64. value == mant * 2^exp.
            private static void DboxFtoa64(ref NumberBuffer number, ulong mant, int exp, bool denorm)
            {
                if ((mant == (1UL << Float64MantBits)) && !denorm)
                {
                    // Algorithm 5.6 (page 24): the significand is an exact power of two, so the lower
                    // boundary is only half as far away as the upper boundary.
                    int k0 = -MulLog10_2MinusLog10_4Over3(exp);
                    U128 phi = DboxPow64(k0, exp, out int beta);
                    DboxRange64(phi, beta, out ulong xi, out ulong zi);

                    if ((exp != 2) && (exp != 3))
                    {
                        xi++;
                    }

                    ulong q = zi / 10;
                    if (xi <= (q * 10))
                    {
                        StoreShortest(ref number, q, -k0 + 1);
                        return;
                    }

                    ulong yru = DboxRoundUp64(phi, beta);
                    if ((exp == -77) && ((yru & 1) != 0))
                    {
                        yru--;
                    }
                    else if (yru < xi)
                    {
                        yru++;
                    }

                    StoreShortest(ref number, yru, -k0);
                    return;
                }

                // kappa = 2 for float64 (section 5.1.3); p10kappa = 100, p10kappa1 = 1000.
                const uint P10Kappa1 = 1000;

                // Algorithm 5.2 (page 15).
                int k = -MulLog10_2(exp);
                U128 phi2 = DboxPow64(2 + k, exp, out int beta2);
                ulong zi2 = DboxMulPow64((mant * 2 + 1) << beta2, phi2, out bool exact);
                // zi2 is bounded below 2^53 * 1000, allowing a smaller reciprocal than general / 1000.
                ulong s = Math.BigMul(zi2, 4_722_366_482_869_645_214UL, out _) >> 8;
                uint r = (uint)(zi2 - (s * P10Kappa1));
                uint deltai = DboxDelta64(phi2, beta2);

                if (r < deltai)
                {
                    if ((r != 0) || !exact || ((mant & 1) == 0))
                    {
                        StoreShortest(ref number, s, -k + 1);
                        return;
                    }
                    s--;
                    r = 1000; // p10kappa * 10
                }
                else if (r == deltai)
                {
                    bool parity = DboxParity64(mant * 2 - 1, phi2, beta2, out bool exact2);
                    if (parity || (exact2 && ((mant & 1) == 0)))
                    {
                        StoreShortest(ref number, s, -k + 1);
                        return;
                    }
                }

                // Algorithm 5.4 (page 18). p10kappa == 100.
                uint d = r + (100 / 2) - (deltai / 2);
                uint t = d / 100;
                ulong yru2 = 10 * s + t;
                if ((d % 100) == 0)
                {
                    bool parity = DboxParity64(mant * 2, phi2, beta2, out bool exact3);
                    if ((parity != (((d - (100 / 2)) % 2) != 0)) || (exact3 && ((yru2 & 1) != 0)))
                    {
                        yru2--;
                    }
                }

                StoreShortest(ref number, yru2, -k);
            }

            // ftoadbox.go: dboxFtoa32 - shortest conversion for float32. value == mant * 2^exp.
            private static void DboxFtoa32(ref NumberBuffer number, uint mant, int exp, bool denorm)
            {
                if ((mant == (1u << Float32MantBits)) && !denorm)
                {
                    // Algorithm 5.6 (page 24).
                    int k0 = -MulLog10_2MinusLog10_4Over3(exp);
                    ulong phi = DboxPow32(k0, exp, out int beta);
                    DboxRange32(phi, beta, out uint xi, out uint zi);

                    if ((exp != 2) && (exp != 3))
                    {
                        xi++;
                    }

                    uint q = zi / 10;
                    if (xi <= (q * 10))
                    {
                        StoreShortest(ref number, q, -k0 + 1);
                        return;
                    }

                    uint yru = DboxRoundUp32(phi, beta);
                    if ((exp == -77) && ((yru & 1) != 0))
                    {
                        yru--;
                    }
                    else if (yru < xi)
                    {
                        yru++;
                    }

                    StoreShortest(ref number, yru, -k0);
                    return;
                }

                // kappa = 1 for float32 (section 5.1.3); p10kappa = 10, p10kappa1 = 100.
                const uint P10Kappa1 = 100;

                // Algorithm 5.2 (page 15).
                int k = -MulLog10_2(exp);
                ulong phi2 = DboxPow32(1 + k, exp, out int beta2);
                uint zi2 = DboxMulPow32((mant * 2 + 1) << beta2, phi2, out bool exact);
                uint s = zi2 / P10Kappa1;
                uint r = zi2 % P10Kappa1;
                uint deltai = DboxDelta32(phi2, beta2);

                if (r < deltai)
                {
                    if ((r != 0) || !exact || ((mant & 1) == 0))
                    {
                        StoreShortest(ref number, s, -k + 1);
                        return;
                    }
                    s--;
                    r = 100; // p10kappa * 10
                }
                else if (r == deltai)
                {
                    bool parity = DboxParity32(mant * 2 - 1, phi2, beta2, out bool exact2);
                    if (parity || (exact2 && ((mant & 1) == 0)))
                    {
                        StoreShortest(ref number, s, -k + 1);
                        return;
                    }
                }

                // Algorithm 5.4 (page 18). p10kappa == 10.
                uint d = r + (10 / 2) - (deltai / 2);
                uint t = d / 10;
                uint yru2 = 10 * s + t;
                if ((d % 10) == 0)
                {
                    bool parity = DboxParity32(mant * 2, phi2, beta2, out bool exact3);
                    if ((parity != (((d - (10 / 2)) % 2) != 0)) || (exact3 && ((yru2 & 1) != 0)))
                    {
                        yru2--;
                    }
                }

                StoreShortest(ref number, yru2, -k);
            }

            // ftoafixed.go: fixedFtoa - formats `digits` (1..18) significant decimal digits of
            // mant * 2^exp, correctly rounded (round-to-nearest, ties-to-even). value == mant * 2^exp.
            private static unsafe void FixedFtoa(ref NumberBuffer number, ulong mant, int exp, int digits)
            {
                Debug.Assert((digits >= 1) && (digits <= 18));
                Debug.Assert(mant != 0);

                // Shift mantissa to occupy 64 bits so the 192-bit product below keeps at least 63 bits
                // in its top word.
                int b = BitOperations.LeadingZeroCount(mant);
                mant <<= b;
                exp -= b;

                // Multiply f = mant * 2^exp by 10^p so the result has `digits` digits plus a rounding bit.
                int p = (digits - 1) - MulLog10_2(63 + exp);
                bool ok = Pow10(p, out ulong powHi, out ulong powLo, out int exp2);
                Debug.Assert(ok, "fixedFtoa: pow10 out of range");
                _ = ok;

                if ((-22 <= p) && (p < 0))
                {
                    // Special case: exact division by 10^(-p) when the mantissa is a multiple of 5^(-p).
                    // Turning the truncating multiply into a ceiling multiply keeps the top 64 bits exact.
                    powLo++;
                }

                Umul192(mant, powHi, powLo, out ulong dm, out ulong lo1, out ulong lo0);
                int de = exp + exp2;

                // Determine whether any bits are truncated from dm (dt != 0 means truncation happened).
                ulong dt;
                if ((0 <= p) && (p <= 55))
                {
                    // 10^p (p <= 55) is exact in 128 bits, so truncation only comes from the low product bits.
                    dt = ((lo1 | lo0) != 0) ? 1UL : 0UL;
                }
                else if ((-22 <= p) && (p < 0) && DivisiblePow5(mant, -p))
                {
                    // The multiply is exact because the mantissa was a multiple of 5^(-p).
                    dt = 0;
                }
                else
                {
                    dt = 1;
                }

                // Multiply by 2^de by shifting, keeping one extra low bit for rounding.
                int shift = -de - 1;
                if ((dm & ((1UL << shift) - 1)) != 0)
                {
                    dt |= 1;
                }
                dm >>= shift;

                // Decimal point position in the eventual digits; updated as digits are trimmed below.
                number.Scale = digits - p;

                // Trim an excess digit if the product produced one too many.
                ulong max = Uint64Pow10[digits] << 1;
                if (dm >= max)
                {
                    ulong rem = dm % 10;
                    dm /= 10;
                    if (rem != 0)
                    {
                        dt |= 1;
                    }
                    number.Scale++;
                }

                // Round to nearest, ties to even, then drop the rounding bit.
                dm += dm & (dt | (dm >> 1)) & 1;
                dm >>= 1;
                if (dm == (max >> 1))
                {
                    // 999... rolled over to 1000...
                    dm = Uint64Pow10[digits - 1];
                    number.Scale++;
                }

                Debug.Assert(dm != 0);
                int count = FormatAndTrim(dm, number.DigitsPtr, out int untrimmedLength);
                Debug.Assert(untrimmedLength == digits);
                _ = untrimmedLength;
                number.Digits[count] = (byte)'\0';
                number.DigitsCount = count;
            }

            // Stores the decimal significand `mant` with value mant * 10^exp into `number`, removing any
            // trailing zeros (which leaves Scale unchanged). Mirrors ftoadbox.go dboxDigits.
            private static unsafe void StoreShortest(ref NumberBuffer number, ulong mant, int exp)
            {
                Debug.Assert(mant != 0);
                int count = FormatAndTrim(mant, number.DigitsPtr, out int untrimmedLength);
                number.Digits[count] = (byte)'\0';
                number.DigitsCount = count;
                number.Scale = untrimmedLength + exp;
            }

            // Writes the decimal digits of `value` (no leading zeros) into `destination`, trimming trailing
            // zeros. Returns the trimmed digit count and reports the untrimmed digit count.
            private static unsafe int FormatAndTrim(ulong value, byte* destination, out int untrimmedLength)
            {
                Debug.Assert(value != 0);

                if (value < 10)
                {
                    destination[0] = (byte)('0' + value);
                    untrimmedLength = 1;
                    return 1;
                }

                int trailingZeroCount = 0;
                while (true)
                {
                    (ulong quotient, ulong remainder) = Math.DivRem(value, 10);
                    if (remainder != 0)
                    {
                        break;
                    }

                    value = quotient;
                    trailingZeroCount++;
                }

                int count = FormattingHelpers.CountDigits(value);
                untrimmedLength = count + trailingZeroCount;
                byte* start = UInt64ToDecChars(destination + count, value);
                Debug.Assert(start == destination);
                return count;
            }

            // math.go: pow10 returns the 128-bit mantissa and binary exponent of 10^e.
            // 10^e == (hi:lo) / 2^128 * 2^exp. Returns false if e is out of range.
            private static bool Pow10(int e, out ulong hi, out ulong lo, out int exp)
            {
                if ((e < Pow10Min) || (e > Pow10Max))
                {
                    hi = 0;
                    lo = 0;
                    exp = 0;
                    return false;
                }

                int index = e - Pow10Min;
                hi = Pow10TabHi[index];
                lo = Pow10TabLo[index];
                exp = 1 + MulLog2_10(e);
                return true;
            }

            // math.go: Floor(x * log10(2)) for -1600 <= x <= 1600.
            private static int MulLog10_2(int x) => (x * 78913) >> 18;

            // math.go: Floor(x * log2(10)) for -500 <= x <= 500.
            private static int MulLog2_10(int x) => (x * 108853) >> 15;

            // ftoadbox.go: Floor(e*log10(2) - log10(4/3)) for e in [-2985, 2936].
            private static int MulLog10_2MinusLog10_4Over3(int e) => ((e * 631305) - 261663) >> 21;

            // math.go: reports whether x is divisible by 5^p (only meaningful for 1 <= p <= 22).
            private static bool DivisiblePow5(ulong x, int p)
                => (1 <= p) && (p <= 22) && ((x * Div5Tab[(p - 1) * 2]) <= Div5Tab[((p - 1) * 2) + 1]);

            // ftoadbox.go: dboxPow64 - precomputed value of the scaled power of ten for float64.
            private static U128 DboxPow64(int k, int e, out int beta)
            {
                Pow10(k, out ulong hi, out ulong lo, out int e1);
                if ((k < 0) || (k > 55))
                {
                    // Matches Go's `phi.Lo++` which increments only the low word (no carry needed here).
                    lo++;
                }
                beta = e + e1 - 1;
                return new U128(hi, lo);
            }

            // ftoadbox.go: dboxPow32 - precomputed value of the scaled power of ten for float32.
            private static ulong DboxPow32(int k, int e, out int beta)
            {
                Pow10(k, out ulong hi, out ulong lo, out int e1);
                _ = lo;
                if ((k < 0) || (k > 27))
                {
                    hi++;
                }
                beta = e + e1 - 1;
                return hi;
            }

            // ftoadbox.go: dboxMulPow64 - integer part of the multiply plus an exactness flag.
            private static ulong DboxMulPow64(ulong u, U128 phi, out bool isInt)
            {
                Umul192Upper128(u, phi, out ulong rHi, out ulong rLo);
                isInt = rLo == 0;
                return rHi;
            }

            // ftoadbox.go: dboxMulPow32.
            private static uint DboxMulPow32(uint u, ulong phi, out bool isInt)
            {
                ulong r = Umul96Upper64(u, phi);
                isInt = (uint)r == 0;
                return (uint)(r >> 32);
            }

            // ftoadbox.go: dboxParity64 - parity of the multiply plus an exactness flag.
            private static bool DboxParity64(ulong mant2, U128 phi, int beta, out bool isInt)
            {
                Umul192Lower128(mant2, phi, out ulong rHi, out ulong rLo);
                bool parity = ((rHi >> (64 - beta)) & 1) != 0;
                isInt = ((rHi << beta) | (rLo >> (64 - beta))) == 0;
                return parity;
            }

            // ftoadbox.go: dboxParity32.
            private static bool DboxParity32(uint mant2, ulong phi, int beta, out bool isInt)
            {
                ulong r = Umul96Lower64(mant2, phi);
                bool parity = ((r >> (64 - beta)) & 1) != 0;
                isInt = (uint)(r >> (32 - beta)) == 0;
                return parity;
            }

            // ftoadbox.go: dboxDelta64 / dboxDelta32.
            private static uint DboxDelta64(U128 phi, int beta) => (uint)(phi.Hi >> (63 - beta));

            private static uint DboxDelta32(ulong phi, int beta) => (uint)(phi >> (63 - beta));

            // ftoadbox.go: dboxRange64 - the left and right float64 endpoints.
            private static void DboxRange64(U128 phi, int beta, out ulong left, out ulong right)
            {
                left = (phi.Hi - (phi.Hi >> (Float64MantBits + 2))) >> (64 - Float64MantBits - 1 - beta);
                right = (phi.Hi + (phi.Hi >> (Float64MantBits + 1))) >> (64 - Float64MantBits - 1 - beta);
            }

            // ftoadbox.go: dboxRange32.
            private static void DboxRange32(ulong phi, int beta, out uint left, out uint right)
            {
                left = (uint)((phi - (phi >> (Float32MantBits + 2))) >> (64 - Float32MantBits - 1 - beta));
                right = (uint)((phi + (phi >> (Float32MantBits + 1))) >> (64 - Float32MantBits - 1 - beta));
            }

            // ftoadbox.go: dboxRoundUp64 / dboxRoundUp32.
            private static ulong DboxRoundUp64(U128 phi, int beta) => ((phi.Hi >> (64 - Float64MantBits - 2 - beta)) + 1) / 2;

            private static uint DboxRoundUp32(ulong phi, int beta) => (uint)((phi >> (64 - Float32MantBits - 2 - beta)) + 1) / 2;

            // math.go: umul192 - the 192-bit product x * (yHi:yLo) as three 64-bit words.
            private static void Umul192(ulong x, ulong yHi, ulong yLo, out ulong hi, out ulong mid, out ulong lo)
            {
                ulong mid1 = Math.BigMul(x, yLo, out lo);
                hi = Math.BigMul(x, yHi, out ulong mid2);
                mid = mid1 + mid2;
                if (mid < mid1)
                {
                    hi++;
                }
            }

            // ftoadbox.go: umul96Upper64 - upper 64 bits (out of 96) of x * y.
            private static ulong Umul96Upper64(uint x, ulong y)
            {
                ulong xyh = (ulong)x * (uint)(y >> 32);
                ulong xyl = (ulong)x * (uint)y;
                return xyh + (xyl >> 32);
            }

            // ftoadbox.go: umul96Lower64 - lower 64 bits (out of 96) of x * y.
            private static ulong Umul96Lower64(uint x, ulong y) => (ulong)x * y;

            // ftoadbox.go: umul192Upper128 - upper 128 bits (out of 192) of x * (yHi:yLo).
            private static void Umul192Upper128(ulong x, U128 y, out ulong hi, out ulong lo)
            {
                ulong rHi = Math.BigMul(x, y.Hi, out ulong rLo);
                ulong t = Math.BigMul(x, y.Lo, out _);

                // uadd128(r, t)
                lo = rLo + t;
                hi = (lo < rLo) ? rHi + 1 : rHi;
            }

            // ftoadbox.go: umul192Lower128 - lower 128 bits (out of 192) of x * (yHi:yLo).
            private static void Umul192Lower128(ulong x, U128 y, out ulong hi, out ulong lo)
            {
                ulong high = x * y.Hi;
                ulong highLowHi = Math.BigMul(x, y.Lo, out lo);
                hi = high + highLowHi;
            }

            // A 128-bit unsigned value stored as high/low 64-bit words, mirroring Go's uint128.
            private readonly struct U128
            {
                public readonly ulong Hi;
                public readonly ulong Lo;

                public U128(ulong hi, ulong lo)
                {
                    Hi = hi;
                    Lo = lo;
                }
            }

            private static ReadOnlySpan<ulong> Uint64Pow10 =>
            [
                1UL, 10UL, 100UL, 1000UL, 10000UL, 100000UL, 1000000UL,
                10000000UL, 100000000UL, 1000000000UL, 10000000000UL,
                100000000000UL, 1000000000000UL, 10000000000000UL,
                100000000000000UL, 1000000000000000UL, 10000000000000000UL,
                100000000000000000UL, 1000000000000000000UL, 10000000000000000000UL,
            ];

            // math.go: div5Tab - flattened pairs of (multiplicative inverse of 5^p, maxUint64 / 5^p),
            // for p in [1, 22].
            private static ReadOnlySpan<ulong> Div5Tab =>
            [
                0xCCCCCCCCCCCCCCCDUL, 0x3333333333333333UL,
                0x8F5C28F5C28F5C29UL, 0x0A3D70A3D70A3D70UL,
                0x1CAC083126E978D5UL, 0x020C49BA5E353F7CUL,
                0xD288CE703AFB7E91UL, 0x0068DB8BAC710CB2UL,
                0x5D4E8FB00BCBE61DUL, 0x0014F8B588E368F0UL,
                0x790FB65668C26139UL, 0x000431BDE82D7B63UL,
                0xE5032477AE8D46A5UL, 0x0000D6BF94D5E57AUL,
                0xC767074B22E90E21UL, 0x00002AF31DC46118UL,
                0x8E47CE423A2E9C6DUL, 0x0000089705F4136BUL,
                0x4FA7F60D3ED61F49UL, 0x000001B7CDFD9D7BUL,
                0x0FEE64690C913975UL, 0x00000057F5FF85E5UL,
                0x3662E0E1CF503EB1UL, 0x000000119799812DUL,
                0xA47A2CF9F6433FBDUL, 0x0000000384B84D09UL,
                0x54186F653140A659UL, 0x00000000B424DC35UL,
                0x7738164770402145UL, 0x0000000024075F3DUL,
                0xE4A4D1417CD9A041UL, 0x000000000734ACA5UL,
                0xC75429D9E5C5200DUL, 0x000000000170EF54UL,
                0xC1773B91FAC10669UL, 0x000000000049C977UL,
                0x26B172506559CE15UL, 0x00000000000EC1E4UL,
                0xD489E3A9ADDEC2D1UL, 0x000000000002F394UL,
                0x90E860BB892C8D5DUL, 0x000000000000971DUL,
                0x502E79BF1B6F4F79UL, 0x0000000000001E39UL,
            ];
        }
    }
}
