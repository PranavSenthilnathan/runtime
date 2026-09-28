// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// Compact data and reconstruction adapted from vitaut/zmij (MIT).
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace System
{
    internal static partial class Number
    {
        internal static partial class UnroundedScaling
        {
            private const int Pow10Min = -307;
            private const int Pow10Max = 341;
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

                // A normalized power is exact iff its exponent is in [0,55].
                // Convert floor(high:low) to ceil represented as high * 2^64 - low.
                bool inexact = (decimalExponent < 0) || (decimalExponent > 55);
                ulong ceilingLow = low + (inexact ? 1UL : 0UL);
                high += ((low != 0) || inexact) ? 1UL : 0UL;
                low = 0 - ceilingLow;
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
