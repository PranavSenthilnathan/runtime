// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// This file is a C# port of the floating-point formatting routines in the Go programming
// language's src/internal/strconv/uscale.go. Those sources are licensed under the 3-clause
// BSD license used by the Go project. See THIRD-PARTY-NOTICES.TXT ("License notice for
// The Go Programming Language") for the full text.
//
// The algorithm is described in "Floating-Point Printing and Parsing Can Be Simple And Fast":
// https://research.swtch.com/fp

using System.Buffers.Text;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System
{
    internal static partial class Number
    {
        internal static partial class UnroundedScaling
        {
            // Overview:
            //
            // Every finite, non-zero input is normalized to:
            //
            //     f = mantissa * 2^exponent, with bit 63 of mantissa set.
            //
            // The central operation is UScale, which changes from that binary fixed-point
            // scale to a decimal one:
            //
            //     UScale(x, e, p) = unrounded(x * 2^e * 10^p)
            //
            // It uses a cached 128-bit approximation of 10^p and one or two 64-bit
            // multiplications. Unlike ordinary rounding, the result retains enough
            // information for the caller to choose floor, ceiling, or round-to-even.
            //
            // An unrounded value appends a half bit and a sticky bit to its integer part:
            //
            //     Real value             Encoded low bits
            //     integer exactly             00
            //     integer < x < half           01
            //     half exactly                 10
            //     half < x < next integer      11
            //                                  ^^
            //                                  |+-- sticky: some bit below 1/2 was set
            //                                  +--- half:   the 1/2 bit
            //
            // Thus Floor(u) is u >> 2, while the other rounding modes differ only in
            // what they add before that shift. The sticky bit is never cleared by later
            // division, so rounding is deferred without losing information.
            //
            // Fixed-width formatting scales f so that rounding produces the requested
            // number of significant digits:
            //
            //     f -- multiply by 10^p --> unrounded candidate -- round --> digits
            //
            // Shortest formatting instead scales the two midpoints around f. Decimal
            // integers inside that interval parse back to f, so selecting from that
            // integer interval directly produces the shortest round-trippable result.

            /// <summary>
            /// Attempts to convert a finite, non-zero <paramref name="value"/> into its decimal digit
            /// representation using fast unrounded scaling.
            /// </summary>
            /// <remarks>
            /// Supported requests are <paramref name="requestedDigits"/> == -1 (shortest round-trippable
            /// representation) and 1..18 significant digits. Any other request returns
            /// <see langword="false"/> so the caller can fall back to Dragon4.
            /// </remarks>
            internal static bool TryRun<TNumber>(TNumber value, int requestedDigits, ref NumberBuffer number)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                if (!TryGetDigits(value, requestedDigits, out ulong digits, out int decimalExponent))
                {
                    return false;
                }

                StoreDigits(ref number, digits, decimalExponent);
                number.CheckConsistency();
                return true;
            }

            // Exposes the existing shortest conversion to the shared presentation layer.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            internal static bool TryGetShortest<TNumber>(TNumber value, out ulong digits, out int decimalExponent)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                if (!TryGetDigits(value, -1, out digits, out decimalExponent))
                {
                    return false;
                }

                TrimTrailingZeros(ref digits, ref decimalExponent);
                return true;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static bool TryGetDigits<TNumber>(TNumber value, int requestedDigits, out ulong digits, out int decimalExponent)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                if ((requestedDigits < -1) || (requestedDigits == 0) || (requestedDigits > 18))
                {
                    digits = 0;
                    decimalExponent = 0;
                    return false;
                }

                Debug.Assert(value != TNumber.Zero);
                Debug.Assert(TNumber.IsFinite(value));

                ulong bits = TNumber.FloatToBits(value);
                int biasedExponent = (int)(bits >> TNumber.DenormalMantissaBits) & TNumber.InfinityExponent;
                ulong mantissa = bits & TNumber.DenormalMantissaMask;
                int exponent = TNumber.MinBinaryExponent - TNumber.DenormalMantissaBits;
                int shift;
                if (biasedExponent != 0)
                {
                    mantissa |= 1UL << TNumber.DenormalMantissaBits;
                    exponent = biasedExponent - TNumber.ExponentBias - TNumber.DenormalMantissaBits;
                    shift = 63 - TNumber.DenormalMantissaBits;
                }
                else
                {
                    shift = BitOperations.LeadingZeroCount(mantissa);
                }
                // In this range the exact integer is also the nearest shortest representation.
                // Larger integers may have a shorter decimal inside the rounding interval.
                if (((uint)(-exponent) <= TNumber.DenormalMantissaBits)
                    && ((mantissa & ((1UL << -exponent) - 1)) == 0))
                {
                    ulong integer = mantissa >> -exponent;
                    if ((requestedDigits == -1) || (FormattingHelpers.CountDigits(integer) <= requestedDigits))
                    {
                        digits = integer;
                        decimalExponent = 0;
                        return true;
                    }
                }

                mantissa <<= shift;
                exponent -= shift;

                if (requestedDigits == -1)
                {
                    digits = ShortFloat<TNumber>(mantissa, exponent, out decimalExponent);
                }
                else
                {
                    digits = FixedWidthFloat(mantissa, exponent, requestedDigits, out decimalExponent);
                }

                return true;
            }

            // Returns the requested significant-digit form of:
            //
            //     f = mantissa * 2^exponent = digits * 10^decimalExponent.
            //
            // Choosing power = n - 1 - floor(log10(f)) places the scaled value in the
            // n-digit range [10^(n-1), 10^n). Log10Pow2 uses the bit length of the
            // normalized mantissa instead of its exact logarithm, so power can be one
            // too large but never too small. That only requires removing one extra digit.
            private static ulong FixedWidthFloat(ulong mantissa, int exponent, int digitCount, out int decimalExponent)
            {
                Debug.Assert((digitCount >= 1) && (digitCount <= 18));

                int power = digitCount - 1 - Log10Pow2(exponent + 63);
                Scaler scaler = Prescale(exponent, power);
                ulong unrounded = UScale(mantissa, in scaler);

                if (unrounded >= ((Unsafe.Add(ref MemoryMarshal.GetReference(ulong.PowersOf10), digitCount) << 2) - 2))
                {
                    // Divide before rounding to avoid double rounding. Preserve prior
                    // inexactness and fold any new remainder into the sticky bit.
                    (ulong quotient, ulong remainder) = Math.DivRem(unrounded, 10);
                    unrounded = quotient | (unrounded & 1) | (remainder != 0 ? 1UL : 0UL);
                    power--;
                }

                decimalExponent = -power;
                return (unrounded + 1 + ((unrounded >> 2) & 1)) >> 2;
            }

            // Computes the shortest decimal form of f = mantissa * 2^exponent that rounds
            // back to the original floating-point value.
            //
            // The midpoints between f and its adjacent floating-point values delimit the
            // interval of real numbers that parse to f:
            //
            //     previous float             f             next float
            //            |---------|----------|----------|---------|
            //                      minimum             maximum
            //
            // Usually both adjacent values are one ulp away, making the interval
            // symmetric. At an exact power of two the exponent changes below f:
            //
            //     previous       f                 next
            //            |-- 1/2 ulp --|------ 1 ulp ------|
            //                    ^ 1/4 ulp       ^ 1/2 ulp
            //                    minimum         maximum
            //
            // Scaling minimum and maximum by the same 10^power converts this real
            // interval into an integer interval [minimumDigits, maximumDigits]. Any
            // integer in that interval, multiplied by 10^-power, is a valid result.
            private static ulong ShortFloat<TNumber>(ulong mantissa, int exponent, out int decimalExponent)
                where TNumber : unmanaged, IBinaryFloatParseAndFormatInfo<TNumber>
            {
                int mantissaBits = TNumber.DenormalMantissaBits;
                int minimumExponent = TNumber.MinBinaryExponent - 63;
                int zeroBits = 63 - mantissaBits;

                ulong minimum;
                ulong maximum;
                int odd;
                int power;

                if (exponent >= minimumExponent)
                {
                    // At a normal power of two, the lower neighbor uses the preceding binary
                    // exponent and is half as far away. Its lower midpoint is therefore only
                    // one quarter ulp below f.
                    power = -Log10Pow2(exponent + zeroBits);
                    minimum = mantissa - (1UL << (zeroBits - 1));
                    maximum = mantissa + (1UL << (zeroBits - 1));
                    odd = (int)((mantissa >> zeroBits) & 1);
                    if ((mantissa == (1UL << 63)) && (exponent > minimumExponent))
                    {
                        power = -Skewed(exponent + zeroBits);
                        minimum = mantissa - (1UL << (zeroBits - 2));
                    }
                }
                // Subnormals retain the minimum binary exponent while their mantissas
                // have fewer significant bits. Account for those additional zero bits
                // when locating the neighboring values in the normalized representation.
                else
                {
                    zeroBits += minimumExponent - exponent;
                    power = -Log10Pow2(exponent + zeroBits);
                    minimum = mantissa - (1UL << (zeroBits - 1));
                    maximum = mantissa + (1UL << (zeroBits - 1));
                    odd = (int)((mantissa >> zeroBits) & 1);
                }

                Scaler scaler = Prescale(exponent, power);

                // IEEE 754 midpoint ties round to the value with an even mantissa. An
                // even input therefore includes exact boundaries; an odd input excludes
                // them. Nudging by odd before ceiling/floor implements that distinction.
                ulong minimumUnrounded = UScale(minimum, in scaler) + (uint)odd;
                ulong maximumUnrounded = UScale(maximum, in scaler) - (uint)odd;
                ulong minimumDigits = (minimumUnrounded + 3) >> 2;
                ulong maximumDigits = maximumUnrounded >> 2;

                // The selected scale makes the interval span at least one and at most
                // ten integers. If it contains a multiple of ten, dropping that zero
                // immediately yields a representation with one fewer decimal digit.
                Debug.Assert(maximumDigits >= minimumDigits);
                Debug.Assert((maximumDigits - minimumDigits) < 10);

                ulong digits = maximumDigits / 10;

                if ((digits * 10) >= minimumDigits)
                {
                    decimalExponent = 1 - power;
                    return digits;
                }

                // With one valid integer there is no choice. With multiple valid
                // integers, choose the one nearest f using round-to-even.
                digits = minimumDigits;
                if (digits < maximumDigits)
                {
                    ulong unrounded = UScale(mantissa, in scaler);
                    digits = (unrounded + 1 + ((unrounded >> 2) & 1)) >> 2;
                }

                decimalExponent = -power;
                return digits;
            }

            // Stores digits * 10^decimalExponent in NumberBuffer form.
            private static void StoreDigits(ref NumberBuffer number, ulong digits, int decimalExponent)
            {
                Debug.Assert(digits != 0);

                TrimTrailingZeros(ref digits, ref decimalExponent);

                int digitCount = FormattingHelpers.CountDigits(digits);
                Span<byte> destination = number.Digits.Slice(0, digitCount);
                int start = UInt64ToDecChars(destination, digitCount, digits);
                Debug.Assert(start == 0);

                number.Scale = digitCount + decimalExponent;
                number.Digits[digitCount] = (byte)'\0';
                number.DigitsCount = digitCount;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void TrimTrailingZeros(ref ulong digits, ref int decimalExponent)
            {
                if (RemoveZeros(ref digits, ref decimalExponent, 1, 0xCCCCCCCCCCCCCCCD, ulong.MaxValue / 10))
                {
                    while (RemoveZeros(ref digits, ref decimalExponent, 8, 0xC767074B22E90E21, ulong.MaxValue / 100000000))
                    {
                    }
                    RemoveZeros(ref digits, ref decimalExponent, 4, 0xD288CE703AFB7E91, ulong.MaxValue / 10000);
                    RemoveZeros(ref digits, ref decimalExponent, 2, 0x8F5C28F5C28F5C29, ulong.MaxValue / 100);
                    RemoveZeros(ref digits, ref decimalExponent, 1, 0xCCCCCCCCCCCCCCCD, ulong.MaxValue / 10);
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static bool RemoveZeros(ref ulong digits, ref int exponent, int zeros, ulong inverse, ulong threshold)
            {
                ulong quotient = BitOperations.RotateRight(digits * inverse, zeros);
                if (quotient > threshold)
                {
                    return false;
                }
                digits = quotient;
                exponent += zeros;
                return true;
            }

            // Returns the scaling constants for:
            //
            //     unrounded(x * 2^binaryExponent * 10^decimalExponent).
            //
            // The table stores a normalized 128-bit approximation of each power of ten
            // as high * 2^64 - low. The shift combines binaryExponent, the cached power's
            // binary scale, and three additional positions: one from normalizing the
            // cached power to bit 127 and two for the half and sticky bits.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static Scaler Prescale(int binaryExponent, int decimalExponent)
            {
                Debug.Assert((decimalExponent >= Pow10Min) && (decimalExponent <= Pow10Max));

                GetPowerOf10(decimalExponent, out ulong high, out ulong low);
                return new Scaler(high, low, -(binaryExponent + Log2Pow10(decimalExponent) + 3));
            }

            // Multiplies value by the cached power high * 2^64 - low and returns the
            // shifted unrounded result. Conceptually the 192-bit product is:
            //
            //                                high word        middle word       low word
            //                             +----------------+----------------+----------------+
            //     value * (high * 2^64)  |      high      |      low       |      zero      |
            //     value * low            |                |      high      |      low       |
            //                             +----------------+----------------+----------------+
            //     difference             |      high      |     middle     |      low       |
            //
            // If bits discarded from the high word already prove the result inexact, the
            // lower correction cannot affect the retained bits and the sticky bit can be
            // set immediately.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static ulong UScale(ulong value, in Scaler scaler)
            {
                ulong high = Math.BigMul(value, scaler.PowerHigh, out ulong middle);
                int shift = scaler.Shift;

                Debug.Assert((uint)shift < 64);

                if ((high & ((1UL << shift) - 1)) != 0)
                {
                    return (high >> shift) | 1;
                }

                ulong middle2 = Math.BigMul(value, scaler.PowerLow, out _);
                high -= middle < middle2 ? 1UL : 0UL;
                return (high >> shift) | ((middle - middle2) > 1 ? 1UL : 0UL);
            }

            // These fixed-point approximations are exact after flooring throughout the
            // binary and decimal exponent ranges supported by float and double.
            //
            // Floor(log10(2^x)).
            private static int Log10Pow2(int value) => (value * 78913) >> 18;

            // Floor(log2(10^x)).
            private static int Log2Pow10(int value) => (value * 108853) >> 15;

            // Floor(log10(3/4 * 2^x)).
            private static int Skewed(int value) => ((value * 631305) - 261663) >> 21;

            private readonly struct Scaler
            {
                public readonly ulong PowerHigh;
                public readonly ulong PowerLow;
                public readonly int Shift;

                public Scaler(ulong powerHigh, ulong powerLow, int shift)
                {
                    PowerHigh = powerHigh;
                    PowerLow = powerLow;
                    Shift = shift;
                }
            }
        }
    }
}
