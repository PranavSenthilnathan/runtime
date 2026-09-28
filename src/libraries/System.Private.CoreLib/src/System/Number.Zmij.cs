// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Text;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System
{
    // This is a port of the Zmij shortest float-to-decimal conversion by Victor Zverovich
    // (https://github.com/vitaut/zmij), via the C# implementations Zmij.NET and ZmijSharp
    // (https://github.com/nuskey8/Zmij.NET, https://github.com/akeit0/ZmijSharp). See THIRD-PARTY-NOTICES.TXT.
    //
    // A value is scaled by one 128-bit power of ten so that the integer part holds all but the last
    // candidate digit; the fractional part decides rounding and whether that last digit is needed.
    // The 128-bit significands of 10^-307..10^341 are reconstructed from a 708-byte compact cache. Bounded
    // precision (1..18 significant digits, ties to even) uses the same table; Dragon4 remains for more.
    internal static partial class Number
    {
        internal static class Zmij
        {
            private const int DoubleSignificandBits = 52;
            private const int DoubleExponentOffset = 1023 + DoubleSignificandBits;
            private const ulong DoubleImplicitBit = 1UL << DoubleSignificandBits;

            private const int ExtraShift = 6;
            private const ulong BiasedHalf = 0x8000_0000_0000_0006UL;

            private const int MinCacheExponent = -307;
            private const int MaxCacheExponent = 341;

            // Produces the shortest round-trippable digits for a finite, non-zero double, float, Half or BFloat16.
            // Returns false for other types.
            public static bool TryRun<TNumber>(TNumber value, ref NumberBuffer number)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                if (!TryGetShortest(value, out ulong significand, out int exponent))
                {
                    return false;
                }

                int length = FormattingHelpers.CountDigits(significand);
                Debug.Assert(length <= 17);

                int start = UInt64ToDecChars(number.Digits, length, significand);
                Debug.Assert(start == 0);

                number.Scale = length + exponent;
                number.Digits[length] = (byte)('\0');
                number.DigitsCount = length;
                return true;
            }

            // Produces the shortest round-trippable value = significand * 10^exponent for a finite, non-zero double,
            // float, Half or BFloat16, with no trailing decimal zeros in the significand. Returns false for other types.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static bool TryGetShortest<TNumber>(TNumber value, out ulong significand, out int exponent)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                ulong bits = TNumber.FloatToBits(value);

                if (typeof(TNumber) == typeof(double))
                {
                    ToDecimal(bits, out significand, out exponent);
                }
                else if ((typeof(TNumber) == typeof(float)) || (typeof(TNumber) == typeof(Half)) || (typeof(TNumber) == typeof(BFloat16)))
                {
                    ToDecimal((uint)bits, TNumber.DenormalMantissaBits, TNumber.ExponentBias, TNumber.InfinityExponent, out significand, out exponent);
                }
                else
                {
                    significand = 0;
                    exponent = 0;
                    return false;
                }

                Debug.Assert(significand != 0);

                // Multiplication by the inverse of 5^k and rotation by k both tests divisibility
                // by 10^k and produces the quotient, avoiding separate remainder and division.
                if (RemoveZeros(ref significand, ref exponent, 1, 0xCCCCCCCCCCCCCCCD, ulong.MaxValue / 10))
                {
                    RemoveZeros(ref significand, ref exponent, 8, 0xC767074B22E90E21, ulong.MaxValue / 100000000);
                    RemoveZeros(ref significand, ref exponent, 4, 0xD288CE703AFB7E91, ulong.MaxValue / 10000);
                    RemoveZeros(ref significand, ref exponent, 2, 0x8F5C28F5C28F5C29, ulong.MaxValue / 100);
                    RemoveZeros(ref significand, ref exponent, 1, 0xCCCCCCCCCCCCCCCD, ulong.MaxValue / 10);
                }

                return true;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static bool RemoveZeros(ref ulong significand, ref int exponent, int zeros, ulong inverse, ulong threshold)
            {
                ulong quotient = BitOperations.RotateRight(significand * inverse, zeros);
                if (quotient > threshold)
                {
                    return false;
                }
                significand = quotient;
                exponent += zeros;
                return true;
            }

            // Produces exactly precision (1..18) significant digits of a finite, non-zero value, correctly rounded
            // with ties to even (the port of write_scientific's fixed-precision path in vitaut/zmij). Returns false
            // when precision is out of that range or the required power of ten is outside the table, in which
            // case the caller falls back to Dragon4.
            public static bool TryRun<TNumber>(TNumber value, int precision, ref NumberBuffer number)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                if ((precision < 1) || (precision > MaxPrecision))
                {
                    return false;
                }

                ulong bits = TNumber.FloatToBits(value);
                int biasedExponent = (int)(bits >> TNumber.DenormalMantissaBits) & TNumber.InfinityExponent;
                ulong significand = bits & TNumber.DenormalMantissaMask;
                int exponent;

                Debug.Assert(biasedExponent != TNumber.InfinityExponent);
                Debug.Assert((biasedExponent | (int)(significand != 0 ? 1 : 0)) != 0);

                if (biasedExponent == 0)
                {
                    exponent = 1 - TNumber.ExponentBias - TNumber.DenormalMantissaBits;
                }
                else
                {
                    significand |= 1UL << TNumber.DenormalMantissaBits;
                    exponent = biasedExponent - TNumber.ExponentBias - TNumber.DenormalMantissaBits;
                }

                // Normalize so that value = significand * 2^exponent with bit 63 of the significand set.
                int leadingZeros = BitOperations.LeadingZeroCount(significand);
                significand <<= leadingZeros;
                exponent -= leadingZeros;

                // Scale by 10^-decimalExponent so that the integral part has precision digits; the estimate uses the
                // lower bound of the value's magnitude, so it can come out one digit too long, never too short.
                int decimalExponent = ComputeDecimalExponent(exponent + 63, regular: true) - (precision - 1);
                if ((-decimalExponent < MinCacheExponent) || (-decimalExponent > MaxCacheExponent))
                {
                    return false;
                }

                int pointShift = -ComputeExponentShift(exponent, decimalExponent);
                Debug.Assert((pointShift >= 1) && (pointShift < 64));

                // High 128 bits of the 192-bit product (pow10High:pow10Low + 1) * significand; the +1 turns the
                // rounded-down power into an upper bound so that a truncated product cannot fake an exact tie.
                GetPowerOf10(-decimalExponent, out ulong pow10High, out ulong pow10Low);
                ulong productHigh = Math.BigMul(pow10High, significand, out ulong productLow);
                ulong lowHigh = Math.BigMul(pow10Low + 1, significand, out _);
                productLow += lowHigh;
                productHigh += (productLow < lowHigh) ? 1UL : 0UL;

                ulong integral = productHigh >> pointShift;
                ulong fraction = productHigh << (64 - pointShift);
                ulong fractionTail = productLow;

                const ulong Half = 1UL << 63;
                bool roundUp = (fraction > Half) || ((fraction == Half) && ((fractionTail != 0) || ((integral & 1) != 0)));
                ulong digits = integral + (roundUp ? 1UL : 0UL);

                if (digits >= Read(Pow10, precision))
                {
                    // One digit too many: round one place coarser, the dropped fraction disambiguating a trailing 5.
                    digits = integral / 10;
                    ulong lastDigit = integral - digits * 10;
                    bool hasFraction = (fraction | fractionTail) != 0;
                    roundUp = (lastDigit > 5) || ((lastDigit == 5) && (hasFraction || ((digits & 1) != 0)));
                    digits += roundUp ? 1UL : 0UL;
                    decimalExponent++;
                }

                Debug.Assert((digits >= Read(Pow10, precision - 1)) && (digits < Read(Pow10, precision)));

                int start = UInt64ToDecChars(number.Digits, precision, digits);
                Debug.Assert(start == 0);

                number.Scale = decimalExponent + precision;
                number.Digits[precision] = (byte)('\0');
                number.DigitsCount = precision;
                return true;
            }

            private const int MaxPrecision = 18;

            // 10^0 .. 10^18
            private static ReadOnlySpan<ulong> Pow10 =>
            [
                1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
                10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000,
                1000000000000000, 10000000000000000, 100000000000000000, 1000000000000000000,
            ];

            private static void ToDecimal(ulong bits, out ulong significand, out int exponent)
            {
                int binaryExponent = (int)((bits << 1) >> (DoubleSignificandBits + 1));
                ulong binarySignificand = bits & (DoubleImplicitBit - 1);

                Debug.Assert(binaryExponent != 0x7FF);
                Debug.Assert((binaryExponent | (int)(binarySignificand != 0 ? 1 : 0)) != 0);

                bool regular;
                if (binaryExponent == 0)
                {
                    // Subnormal: no implicit bit and a symmetric rounding interval.
                    binaryExponent = 1;
                    regular = true;
                }
                else
                {
                    // Powers of two (zero fraction) have an asymmetric interval below them.
                    regular = binarySignificand != 0;
                    binarySignificand |= DoubleImplicitBit;

                    // Integers below 2^53 are their own shortest representation; the caller strips trailing zeros.
                    int shift = DoubleExponentOffset - binaryExponent;
                    if (((uint)shift <= DoubleSignificandBits) && ((binarySignificand & ((1UL << shift) - 1)) == 0))
                    {
                        significand = binarySignificand >> shift;
                        exponent = 0;
                        return;
                    }
                }

                ulong integral = ToDecimal(binarySignificand, binaryExponent, regular, out int decimalExponent, out int lastDigit);
                if (lastDigit >= 0)
                {
                    significand = integral * 10 + (uint)lastDigit;
                    exponent = decimalExponent;
                }
                else
                {
                    significand = integral;
                    exponent = decimalExponent + 1;
                }
            }

            // The 32-bit core is parameterized by the format: significandBits explicit bits, exponentBias and the
            // all-ones exponent. It serves float (23, 127, 0xFF), Half (10, 15, 0x1F) and BFloat16 (7, 127, 0xFF).
            private static void ToDecimal(uint bits, int significandBits, int exponentBias, int exponentMask, out ulong significand, out int exponent)
            {
                int binaryExponent = (int)(bits >> significandBits) & exponentMask;
                uint implicitBit = 1u << significandBits;
                uint binarySignificand = bits & (implicitBit - 1);
                int exponentOffset = exponentBias + significandBits;

                Debug.Assert(binaryExponent != exponentMask);

                bool regular;
                if (binaryExponent == 0)
                {
                    binaryExponent = 1;
                    regular = true;
                }
                else
                {
                    regular = binarySignificand != 0;
                    binarySignificand |= implicitBit;

                    // Integers below 2^(significandBits + 1) are their own shortest representation; the caller strips trailing zeros.
                    int shift = exponentOffset - binaryExponent;
                    if (((uint)shift <= (uint)significandBits) && ((binarySignificand & ((1U << shift) - 1)) == 0))
                    {
                        significand = binarySignificand >> shift;
                        exponent = 0;
                        return;
                    }
                }

                ulong integral = ToDecimal32(binarySignificand, binaryExponent, exponentOffset, regular, out int decimalExponent, out int lastDigit);
                if (lastDigit >= 0)
                {
                    significand = integral * 10 + (uint)lastDigit;
                    exponent = decimalExponent;
                }
                else
                {
                    significand = integral;
                    exponent = decimalExponent + 1;
                }
            }

            // Returns the integral part of the scaled value; lastDigit is -1 when the integral part alone is
            // the shortest representation, otherwise the extra digit to append.
            private static ulong ToDecimal(ulong binarySignificand, int rawExponent, bool regular, out int decimalExponent, out int lastDigit)
            {
                int binaryExponent = rawExponent - DoubleExponentOffset;

                if (!regular)
                {
                    int decExp = ComputeDecimalExponent(binaryExponent, regular: false);
                    int shift = ComputeExponentShift(binaryExponent, decExp + 1) + ExtraShift;
                    GetPowerOf10(-decExp - 1, out ulong pow10High, out ulong pow10Low);
                    ulong y = binarySignificand << shift;
                    ulong productHigh = Math.BigMul(pow10High, y, out ulong productLow);
                    ulong lowProductHigh = Math.BigMul(pow10Low, y, out _);
                    ulong sumLow = productLow + lowProductHigh;
                    ulong sumHigh = productHigh + ((sumLow < productLow) ? 1UL : 0UL);

                    ulong integral = sumHigh >> ExtraShift;
                    ulong fractional = (sumHigh << (64 - ExtraShift)) | (sumLow >> ExtraShift);
                    ulong halfUlp = pow10High >> (ExtraShift + 1 - shift);
                    // The lower half-ulp gets the same one-unit allowance the regular path gives even significands
                    // (a power of two is always even): a candidate exactly on the lower boundary round-trips under
                    // ties-to-even. Only the coarse 16-bit formats reach such candidates (Half 8192 -> "8190",
                    // 16384 -> "16380"); no float or double does.
                    ulong halfUlpLow = (halfUlp >> 1) + 1;
                    bool roundUp = halfUlp > ulong.MaxValue - fractional;
                    bool roundDown = halfUlpLow > fractional;
                    // When both shorter candidates fit, take the nearer one (ties to the even candidate).
                    bool preferUp = roundUp && (!roundDown || (fractional > (1UL << 63)) || ((fractional == (1UL << 63)) && ((integral & 1) != 0)));
                    integral += preferUp ? 1UL : 0UL;

                    int digit = (int)Multiply128AddHigh64(fractional, 10, 0x7FFF_FFFF_FFFF_FFFFUL);
                    int lowDigit = (int)Multiply128AddHigh64(fractional - halfUlpLow, 10, ulong.MaxValue);
                    if (digit < lowDigit)
                    {
                        digit = lowDigit;
                    }

                    decimalExponent = decExp;
                    lastDigit = (!roundUp && !roundDown) ? digit : -1;
                    return integral;
                }

                int decimalExp = ComputeDecimalExponent(binaryExponent, regular: true);
                int regularShift = ComputeExponentShift(binaryExponent, decimalExp + 1) + ExtraShift;
                ulong even = 1UL - (binarySignificand & 1UL);
                GetPowerOf10(-decimalExp - 1, out ulong powHigh, out ulong powLow);
                ulong scaled = binarySignificand << regularShift;
                ulong pHigh = Math.BigMul(powHigh, scaled, out ulong pLow);
                ulong lowHigh = Math.BigMul(powLow, scaled, out _);
                pLow += lowHigh;
                pHigh += (pLow < lowHigh) ? 1UL : 0UL;

                ulong integralPart = pHigh >> ExtraShift;
                ulong fractionalPart = (pHigh << (64 - ExtraShift)) | (pLow >> ExtraShift);
                ulong halfUlpRegular = (powHigh >> (ExtraShift + 1 - regularShift)) + even;
                bool roundUpRegular = fractionalPart + halfUlpRegular < fractionalPart;
                bool roundDownRegular = halfUlpRegular > fractionalPart;
                integralPart += roundUpRegular ? 1UL : 0UL;

                int extraDigit = (int)Multiply128AddHigh64(fractionalPart, 10, BiasedHalf);
                if (fractionalPart == (1UL << 62))
                {
                    extraDigit = 2;
                }

                decimalExponent = decimalExp;
                lastDigit = (!roundUpRegular && !roundDownRegular) ? extraDigit : -1;
                return integralPart;
            }

            private static ulong ToDecimal32(uint binarySignificand, int rawExponent, int exponentOffset, bool regular, out int decimalExponent, out int lastDigit)
            {
                int binaryExponent = rawExponent - exponentOffset;

                if (!regular)
                {
                    int decExp = ComputeDecimalExponent(binaryExponent, regular: false);
                    int shift = ComputeExponentShift(binaryExponent, decExp + 1) + ExtraShift;
                    GetPowerOf10(-decExp - 1, out ulong pow10High, out ulong pow10Low);
                    ulong y = (ulong)binarySignificand << shift;
                    ulong productHigh = Math.BigMul(pow10High, y, out ulong productLow);
                    ulong lowProductHigh = Math.BigMul(pow10Low, y, out _);
                    ulong sumLow = productLow + lowProductHigh;
                    ulong sumHigh = productHigh + ((sumLow < productLow) ? 1UL : 0UL);

                    ulong integral = sumHigh >> ExtraShift;
                    ulong fractional = (sumHigh << (64 - ExtraShift)) | (sumLow >> ExtraShift);
                    ulong halfUlp = pow10High >> (ExtraShift + 1 - shift);
                    // The lower half-ulp gets the same one-unit allowance the regular path gives even significands
                    // (a power of two is always even): a candidate exactly on the lower boundary round-trips under
                    // ties-to-even. Only the coarse 16-bit formats reach such candidates (Half 8192 -> "8190",
                    // 16384 -> "16380"); no float or double does.
                    ulong halfUlpLow = (halfUlp >> 1) + 1;
                    bool roundUp = halfUlp > ulong.MaxValue - fractional;
                    bool roundDown = halfUlpLow > fractional;
                    // When both shorter candidates fit, take the nearer one (ties to the even candidate).
                    bool preferUp = roundUp && (!roundDown || (fractional > (1UL << 63)) || ((fractional == (1UL << 63)) && ((integral & 1) != 0)));
                    integral += preferUp ? 1UL : 0UL;

                    int digit = (int)Multiply128AddHigh64(fractional, 10, 0x7FFF_FFFF_FFFF_FFFFUL);
                    int lowDigit = (int)Multiply128AddHigh64(fractional - halfUlpLow, 10, ulong.MaxValue);
                    if (digit < lowDigit)
                    {
                        digit = lowDigit;
                    }

                    decimalExponent = decExp;
                    lastDigit = (!roundUp && !roundDown) ? digit : -1;
                    return integral;
                }

                const int SingleExtraShift = 34;

                int decimalExp = ComputeDecimalExponent(binaryExponent, regular: true);
                int regularShift = ComputeExponentShift(binaryExponent, decimalExp + 1) + SingleExtraShift;
                ulong even = 1UL - (binarySignificand & 1U);
                GetPowerOf10(-decimalExp - 1, out ulong pow10HighRegular, out _);
                ulong product = Math.BigMul(pow10HighRegular + 1, (ulong)binarySignificand << regularShift, out _);

                ulong integralPart = product >> SingleExtraShift;
                ulong fractionalPart = product & ((1UL << SingleExtraShift) - 1);
                ulong halfUlpRegular = (pow10HighRegular >> (65 - regularShift)) + even;
                bool roundUpRegular = ((fractionalPart + halfUlpRegular) >> SingleExtraShift) != 0;
                bool roundDownRegular = halfUlpRegular > fractionalPart;
                integralPart += roundUpRegular ? 1UL : 0UL;

                int extraDigit = (int)((fractionalPart * 10 + (1UL << (SingleExtraShift - 1))) >> SingleExtraShift);
                if (fractionalPart == (1UL << (SingleExtraShift - 2)))
                {
                    extraDigit = 2;
                }

                decimalExponent = decimalExp;
                lastDigit = (!roundUpRegular && !roundDownRegular) ? extraDigit : -1;
                return integralPart;
            }

            // floor(binaryExponent * log10(2)) for regular values, floor((binaryExponent - log2(4/3)... ) * log10(2)) otherwise.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static int ComputeDecimalExponent(int binaryExponent, bool regular)
            {
                const int Log10ThreeOverFourSignificand = 131_072;
                const int Log10TwoSignificand = 315_653;
                const int Log10TwoExponent = 20;
                return (binaryExponent * Log10TwoSignificand - (regular ? 0 : Log10ThreeOverFourSignificand)) >> Log10TwoExponent;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static int ComputeExponentShift(int binaryExponent, int decimalExponent)
            {
                const int Log2Pow10Significand = 217_707;
                const int Log2Pow10Exponent = 16;
                int pow10BinaryExponent = (-decimalExponent * Log2Pow10Significand) >> Log2Pow10Exponent;
                return binaryExponent + pow10BinaryExponent + 1;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static ulong Multiply128AddHigh64(ulong x, ulong y, ulong c)
            {
                ulong high = Math.BigMul(x, y, out ulong low);
                low += c;
                return high + ((low < c) ? 1UL : 0UL);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static T Read<T>(ReadOnlySpan<T> table, int index) where T : struct
            {
                Debug.Assert((uint)index < (uint)table.Length);
                return Unsafe.Add(ref MemoryMarshal.GetReference(table), (nint)index);
            }

            // The normalized 128-bit significand of 10^decimalExponent, reconstructed from 708 bytes.
            // Dougall Johnson's compact power reconstruction, from vitaut/zmij.
            // See THIRD-PARTY-NOTICES.TXT for the Zmij MIT license.
            private static void GetPowerOf10(int decimalExponent, out ulong high, out ulong low)
            {
                Debug.Assert((decimalExponent >= -307) && (decimalExponent <= 341));
                int index = decimalExponent + 307;
                int majorIndex = ((index + 24) / 28) * 2;
                ulong multiplier = Unsafe.Add(ref MemoryMarshal.GetReference(CompactMinor), (index + 24) % 28);
                ulong majorHigh = Unsafe.Add(ref MemoryMarshal.GetReference(CompactMajor), majorIndex);
                ulong majorLow = Unsafe.Add(ref MemoryMarshal.GetReference(CompactMajor), majorIndex + 1);
                ulong middle = Math.BigMul(majorLow, multiplier, out ulong lower);
                ulong upper = Math.BigMul(majorHigh, multiplier, out ulong tail);
                tail += middle;
                upper += tail < middle ? 1UL : 0UL;
                if ((upper >> 63) != 0)
                {
                    high = upper;
                    low = tail;
                }
                else
                {
                    high = (upper << 1) | (tail >> 63);
                    low = (tail << 1) | (lower >> 63);
                }
                low -= (Unsafe.Add(ref MemoryMarshal.GetReference(CompactFixups), index >> 5) >> (index & 31)) & 1;
            }

            private static ReadOnlySpan<ulong> CompactMinor =>
            [
                0x8000000000000000UL, 0xA000000000000000UL, 0xC800000000000000UL,
                0xFA00000000000000UL, 0x9C40000000000000UL, 0xC350000000000000UL,
                0xF424000000000000UL, 0x9896800000000000UL, 0xBEBC200000000000UL,
                0xEE6B280000000000UL, 0x9502F90000000000UL, 0xBA43B74000000000UL,
                0xE8D4A51000000000UL, 0x9184E72A00000000UL, 0xB5E620F480000000UL,
                0xE35FA931A0000000UL, 0x8E1BC9BF04000000UL, 0xB1A2BC2EC5000000UL,
                0xDE0B6B3A76400000UL, 0x8AC7230489E80000UL, 0xAD78EBC5AC620000UL,
                0xD8D726B7177A8000UL, 0x878678326EAC9000UL, 0xA968163F0A57B400UL,
                0xD3C21BCECCEDA100UL, 0x84595161401484A0UL, 0xA56FA5B99019A5C8UL,
                0xCECB8F27F4200F3AUL,
            ];

            private static ReadOnlySpan<ulong> CompactMajor =>
            [
                0xADDCB9E83C6B1793UL, 0xDF4ABE242A1BBF3EUL, 0xAF8E5410288E1B6FUL,
                0x07ECF0AE5EE44DDAUL, 0xB1442798F49FFB4AUL, 0x99CD11CFDF41779DUL,
                0xB2FE3F0B8599EF07UL, 0x861FA7E6DCB4AA15UL, 0xB4BCA50B065ABE63UL,
                0x0FED077A756B53AAUL, 0xB67F6455292CBF08UL, 0x1A3BC84C17B1D543UL,
                0xB84687C269EF3BFBUL, 0x3D5D514F40EEA742UL, 0xBA121A4650E4DDEBUL,
                0x92F34D62616CE413UL, 0xBBE226EFB628AFEAUL, 0x890489F70A55368CUL,
                0xBDB6B8E905CB600FUL, 0x5400E987BBC1C921UL, 0xBF8FDB78849A5F96UL,
                0xDE98520472BDD034UL, 0xC16D9A0095928A27UL, 0x75B7053C0F178294UL,
                0xC350000000000000UL, 0x0000000000000000UL, 0xC5371912364CE305UL,
                0x6C28000000000000UL, 0xC722F0EF9D80AAD6UL, 0x424D3AD2B7B97EF6UL,
                0xC913936DD571C84CUL, 0x03BC3A19CD1E38EAUL, 0xCB090C8001AB551CUL,
                0x5CADF5BFD3072CC6UL, 0xCD036837130890A1UL, 0x36DBA887C37A8C10UL,
                0xCF02B2C21207EF2EUL, 0x94F967E45E03F4BCUL, 0xD106F86E69D785C7UL,
                0xE13336D701BEBA52UL, 0xD31045A8341CA07CUL, 0x1EDE48111209A051UL,
                0xD51EA6FA85785631UL, 0x552A74227F3EA566UL, 0xD732290FBACAF133UL,
                0xA97C177947AD4096UL, 0xD94AD8B1C7380874UL, 0x18375281AE7822BDUL,
                0xDB68C2CA82ED2A05UL, 0xA67398DB9F6820E1UL,
            ];

            private static ReadOnlySpan<uint> CompactFixups =>
            [
                0x8D8FC810U, 0x06100293U, 0x19000000U,
                0x00100000U, 0x00000908U, 0x00000000U,
                0x04E00300U, 0x3807E0B2U, 0x3D83D793U,
                0x0006F5CCU, 0x00000000U, 0xFFFF0000U,
                0x8076337DU, 0x4FF45BA0U, 0x09405033U,
                0x034376D9U, 0x09000000U, 0x4E100501U,
                0x076D14DCU, 0xF964F45EU, 0x0000003DU,
            ];


        }
    }
}
