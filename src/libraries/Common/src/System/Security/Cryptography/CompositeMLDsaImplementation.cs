// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;

namespace System.Security.Cryptography
{
    internal sealed partial class CompositeMLDsaImplementation : CompositeMLDsa
    {
        internal static partial bool SupportsAny() => false;

        public CompositeMLDsaImplementation(CompositeMLDsaAlgorithm algorithm)
            : base(algorithm)
        {
            throw new PlatformNotSupportedException();
        }
    }
}
