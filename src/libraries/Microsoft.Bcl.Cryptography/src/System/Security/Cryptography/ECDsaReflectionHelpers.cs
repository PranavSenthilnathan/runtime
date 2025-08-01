// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Reflection;

namespace System.Security.Cryptography
{
    internal static class ECDsaReflectionHelpers
    {
        private static bool? _initializedSuccessfully;

        private static Type? s_ECParametersType;
        private static Type? s_ECCurveType;
        private static Type? s_ECPointType;

        private static MethodInfo? s_ECDsaCreateFromECParametersMethod;
        private static MethodInfo? s_ECDsaCreateFromECCurveMethod;
        private static MethodInfo? s_ECCurveCreateFromOidMethod;

        private static FieldInfo? s_ECParametersCurveField;
        private static FieldInfo? s_ECParametersQField;
        private static FieldInfo? s_ECParametersDField;

        private static FieldInfo? s_ECPointXField;
        private static FieldInfo? s_ECPointYField;

        private static void EnsureInitialized()
        {
            if (_initializedSuccessfully is bool success)
            {
                if (success)
                {
                    return;
                }
                else
                {
                    // TODO resx
                    throw new PlatformNotSupportedException();
                }
            }

            try
            {
                s_ECParametersType = typeof(ECDsa).Assembly.GetType("System.Security.Cryptography.ECParameters", throwOnError: true);
                s_ECCurveType = typeof(ECDsa).Assembly.GetType("System.Security.Cryptography.ECCurve", throwOnError: true);
                s_ECPointType = typeof(ECDsa).Assembly.GetType("System.Security.Cryptography.ECPoint", throwOnError: true);

                s_ECDsaCreateFromECParametersMethod = typeof(ECDsa).GetMethod("Create", [s_ECParametersType]);
                s_ECDsaCreateFromECCurveMethod = typeof(ECDsa).GetMethod("Create", [s_ECCurveType]);

#pragma warning disable IL2080 // 'this' argument does not satisfy 'DynamicallyAccessedMembersAttribute' in call to target method. The source field does not have matching annotations.
                s_ECCurveCreateFromOidMethod = s_ECCurveType.GetMethod("CreateFromOid");

                s_ECParametersCurveField = s_ECParametersType.GetField("Curve");
                s_ECParametersQField = s_ECParametersType.GetField("Q");
                s_ECParametersDField = s_ECParametersType.GetField("D");

                s_ECPointXField = s_ECPointType.GetField("X");
                s_ECPointYField = s_ECPointType.GetField("Y");
#pragma warning restore IL2080 // 'this' argument does not satisfy 'DynamicallyAccessedMembersAttribute' in call to target method. The source field does not have matching annotations.

                _initializedSuccessfully = true;
            }
            catch // TODO should we catch all exceptions?
            {
                _initializedSuccessfully = false;

                // TODO resx
                throw new PlatformNotSupportedException();
            }
        }

        internal static ECDsa CreateECDsa(ECParameters parameters)
        {
            EnsureInitialized();

            return (ECDsa)s_ECDsaCreateFromECParametersMethod.Invoke(null, [CreateNetFrameworkECParameters(parameters)]);
        }

        internal static ECDsa CreateECDsa(ECCurve curve)
        {
            EnsureInitialized();

            return (ECDsa)s_ECDsaCreateFromECCurveMethod.Invoke(null, [CreateNetFrameworkECCurve(curve)]);
        }

        private static object CreateNetFrameworkECParameters(ECParameters parameters)
        {
            EnsureInitialized();

#pragma warning disable IL2077 // Target parameter argument does not satisfy 'DynamicallyAccessedMembersAttribute' in call to target method. The source field does not have matching annotations.
            object ret = Activator.CreateInstance(s_ECParametersType)!;
#pragma warning restore IL2077 // Target parameter argument does not satisfy 'DynamicallyAccessedMembersAttribute' in call to target method. The source field does not have matching annotations.

            s_ECParametersCurveField.SetValue(ret, CreateNetFrameworkECCurve(parameters.Curve));
            s_ECParametersQField.SetValue(ret, CreateNetFrameworkECPoint(parameters.Q));
            s_ECParametersDField.SetValue(ret, parameters.D);

            return ret;
        }

        private static object CreateNetFrameworkECCurve(ECCurve ecCurve)
        {
            EnsureInitialized();

            if (!ecCurve.IsNamed)
            {
                Debug.Fail("This method should only be called with a named curve.");
                throw new CryptographicException();
            }

            return s_ECCurveCreateFromOidMethod.Invoke(null, [ecCurve.Oid])!;
        }

        private static object CreateNetFrameworkECPoint(ECPoint ecPoint)
        {
            EnsureInitialized();

#pragma warning disable IL2077 // Target parameter argument does not satisfy 'DynamicallyAccessedMembersAttribute' in call to target method. The source field does not have matching annotations.
            object ret = Activator.CreateInstance(s_ECPointType)!;
#pragma warning restore IL2077 // Target parameter argument does not satisfy 'DynamicallyAccessedMembersAttribute' in call to target method. The source field does not have matching annotations.

            if (ecPoint.X is byte[] x)
            {
                s_ECPointXField.SetValue(ret, x);
            }

            if (ecPoint.Y is byte[] y)
            {
                s_ECPointYField.SetValue(ret, y);
            }

            return ret;
        }
    }
}
