// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;

namespace System.Security.Cryptography
{
    [Experimental(Experimentals.PostQuantumCryptographyDiagId, UrlFormat = Experimentals.SharedUrlFormat)]
    public sealed class CompositeMLDsaAlgorithm
    {
        public int MaxSignatureSizeInBytes { get; }

        internal MLDsaAlgorithm MLDsaAlgorithm { get; }
        internal string Oid { get; }

        private CompositeMLDsaAlgorithm(
            MLDsaAlgorithm mlDsaAlgorithm,
            int maxSignatureSize,
            string oid)
        {
            MLDsaAlgorithm = mlDsaAlgorithm;
            MaxSignatureSizeInBytes = maxSignatureSize;
            Oid = oid;
        }

        public CompositeMLDsaAlgorithm MLDsa44WithRSA2048Pss = new(MLDsaAlgorithm.MLDsa44, )

        internal static CompositeMLDsaAlgorithm? GetAlgorithmFromOid(string? oid)
        {
            return oid switch
            {
                "2.16.840.1.114027.80.8.1.100" 

                _ => null,
            };
        }
    }
}
