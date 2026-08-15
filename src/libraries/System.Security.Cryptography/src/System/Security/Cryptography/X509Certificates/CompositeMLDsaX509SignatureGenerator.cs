// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Formats.Asn1;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed class CompositeMLDsaX509SignatureGenerator : X509SignatureGenerator
    {
        private readonly CompositeMLDsa _key;
        private readonly PublicKey _publicKey;

        internal CompositeMLDsaX509SignatureGenerator(CompositeMLDsa key)
        {
            _key = key;

            byte[] subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
            _publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
        }

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
        {
            // Composite ML-DSA AlgorithmIdentifiers do not have parameters.
            AsnWriter writer = new(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteObjectIdentifier(_key.Algorithm.Oid);
            writer.PopSequence();
            return writer.Encode();
        }

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) =>
            _key.SignData(data);

        protected override PublicKey BuildPublicKey() => _publicKey;
    }
}
