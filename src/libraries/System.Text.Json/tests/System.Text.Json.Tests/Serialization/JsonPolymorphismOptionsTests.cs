// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json.Serialization.Metadata;
using Xunit;
using static System.Text.Json.Serialization.Tests.PolymorphicTests;

namespace System.Text.Json.Serialization.Tests
{
    public static class JsonPolymorphismOptionsTests
    {
        [Fact]
        public static void JsonPolymorphismOptions_DefaultInstance()
        {
            var options = new JsonPolymorphismOptions();

            Assert.False(options.IgnoreUnrecognizedTypeDiscriminators);
            Assert.Equal(JsonUnknownDerivedTypeHandling.FailSerialization, options.UnknownDerivedTypeHandling);
            Assert.Equal("$type", options.TypeDiscriminatorPropertyName);
            Assert.Empty(options.DerivedTypes);
        }

        [Theory]
        [MemberData(nameof(GetDerivedTypes))]
        public static void JsonPolymorphismOptions_AddDerivedTypes(JsonDerivedType[] derivedTypes)
        {
            var options = new JsonPolymorphismOptions();
            foreach (JsonDerivedType derivedType in derivedTypes)
            {
                options.DerivedTypes.Add(derivedType);
            }

            Assert.Equal(derivedTypes, options.DerivedTypes);
        }

        public static IEnumerable<object[]> GetDerivedTypes()
        {
            yield return WrapArgs(default(JsonDerivedType));
            yield return WrapArgs(new JsonDerivedType(typeof(int)));
            yield return WrapArgs(new JsonDerivedType(typeof(void), "void"));
            yield return WrapArgs(new JsonDerivedType(typeof(object), 42));
            yield return WrapArgs(new JsonDerivedType(typeof(string)));
            yield return WrapArgs(
                new JsonDerivedType(typeof(JsonSerializerOptions)),
                new JsonDerivedType(typeof(int), 42),
                new JsonDerivedType(typeof(void), "void"));

            static object[] WrapArgs(params JsonDerivedType[] derivedTypes) => new object[] { derivedTypes };
        }

        [Fact]
        public static void JsonPolymorphismOptions_AssigningOptionsToJsonTypeInfoKindNone_ThrowsInvalidOperationException()
        {
            var options = new JsonPolymorphismOptions();
            JsonTypeInfo jti = JsonTypeInfo.CreateJsonTypeInfo(typeof(int), new());
            Assert.Equal(JsonTypeInfoKind.None, jti.Kind);

            Assert.Throws<InvalidOperationException>(() => jti.PolymorphismOptions = options);
        }

        [Fact]
        public static void JsonPolymorphismOptions_AssigningOptionsToSecondJsonTypeInfo_ThrowsInvalidOperationException()
        {
            var options = new JsonPolymorphismOptions();

            JsonTypeInfo jti1 = JsonTypeInfo.CreateJsonTypeInfo(typeof(PolymorphicClass), new());
            jti1.PolymorphismOptions = options;

            JsonTypeInfo jti2 = JsonTypeInfo.CreateJsonTypeInfo(typeof(PolymorphicClass), new());
            Assert.Throws<ArgumentException>(() => jti2.PolymorphismOptions = options);
        }

        [Fact]
        public static void JsonPolymorphismOptions_CreateBlankJsonTypeInfo_ContainsNoPolymorphismMetadata()
        {
            JsonSerializerOptions options = JsonSerializerOptions.Default;

            // Sanity check: type returns polymorphism options using the default resolver
            JsonTypeInfo jti = options.TypeInfoResolver.GetTypeInfo(typeof(PolymorphicClass), options);
            Assert.NotNull(jti.PolymorphismOptions);

            // Blank instance should not contain polymorphism options
            jti = JsonTypeInfo.CreateJsonTypeInfo(typeof(PolymorphicClass), options);
            Assert.Null(jti.PolymorphismOptions);
        }

        [Theory]
        [InlineData(typeof(int))]
        [InlineData(typeof(string))]
        [InlineData(typeof(object))]
        [InlineData(typeof(DateTime))]
        [InlineData(typeof(IEnumerable<int>))]
        [InlineData(typeof(PolymorphicClass))]
        [InlineData(typeof(PolymorphicClass.DerivedClass1_NoTypeDiscriminator))]
        [InlineData(typeof(PolymorphicClass.DerivedClass1_TypeDiscriminator))]
        [InlineData(typeof(PolymorphicClassWithConstructor))]
        [InlineData(typeof(PolymorphicList))]
        [InlineData(typeof(PolymorphicDictionary))]
        [InlineData(typeof(PolymorphicClassWithCustomTypeDiscriminator))]
        [InlineData(typeof(PolymorphicClassWithoutDerivedTypeAttribute))]
        [InlineData(typeof(PolymorphicClass_InvalidCustomTypeDiscriminatorPropertyName))]
        [InlineData(typeof(PolymorphicClassWithNullDerivedTypeAttribute))]
        [InlineData(typeof(PolymorphicClassWithStructDerivedTypeAttribute))]
        [InlineData(typeof(PolymorphicClassWithObjectDerivedTypeAttribute))]
        [InlineData(typeof(PolymorphicClassWithNonAssignableDerivedTypeAttribute))]
        [InlineData(typeof(PolymorphicAbstractClassWithAbstractClassDerivedType))]
        [InlineData(typeof(PolymorphicClassWithDuplicateDerivedTypeRegistrations))]
        [InlineData(typeof(PolymorphicClasWithDuplicateTypeDiscriminators))]
        [InlineData(typeof(PolymorphicGenericClass<int>))]
        [InlineData(typeof(PolymorphicDerivedGenericClass.DerivedClass<int>))]
        [InlineData(typeof(PolymorphicClass_CustomConverter_TypeDiscriminator))]
        [InlineData(typeof(PolymorphicClass_CustomConverter_NoTypeDiscriminator))]
        public static void DefaultResolver_ReportsCorrectPolymorphismMetadata(Type polymorphicType)
        {
            JsonPolymorphicAttribute? polymorphicAttribute = polymorphicType.GetCustomAttribute<JsonPolymorphicAttribute>(inherit: false);
            JsonDerivedTypeAttribute[] derivedTypeAttributes = polymorphicType.GetCustomAttributes<JsonDerivedTypeAttribute>(inherit: false).ToArray();

            JsonSerializer.Serialize(42); // Ensure default converters have been rooted
            var options = JsonSerializerOptions.Default;
            JsonTypeInfo jsonTypeInfo = options.TypeInfoResolver.GetTypeInfo(polymorphicType, options);

            Assert.Equal(polymorphicType, jsonTypeInfo.Type);

            JsonPolymorphismOptions? polyOptions = jsonTypeInfo.PolymorphismOptions;
            if (polymorphicAttribute == null && derivedTypeAttributes.Length == 0)
            {
                Assert.Null(polyOptions);
            }
            else
            {
                Assert.NotNull(polyOptions);

                Assert.Equal(polymorphicAttribute?.IgnoreUnrecognizedTypeDiscriminators ?? false, polyOptions.IgnoreUnrecognizedTypeDiscriminators);
                Assert.Equal(polymorphicAttribute?.UnknownDerivedTypeHandling ?? default, polyOptions.UnknownDerivedTypeHandling);
                Assert.Equal(polymorphicAttribute?.TypeDiscriminatorPropertyName ?? "$type", polyOptions.TypeDiscriminatorPropertyName);
                Assert.Equal(
                    expected: derivedTypeAttributes.Select(attr => (attr.DerivedType, attr.TypeDiscriminator)),
                    actual: polyOptions.DerivedTypes.Select(attr => (attr.DerivedType, attr.TypeDiscriminator)));
            }
        }

        [Fact]
        public static void CompositeOptions()
        {
            var opt = new JsonSerializerOptions();
            opt.Converters.Add(new CustomConverterFactory(opt));

            string json = """{"$type":"Derived","Name":"Alice"}""";

            // Payload supported with strict options
            Base? deserialized = JsonSerializer.Deserialize<Base>(json, opt);
            Assert.IsType<Derived>(deserialized);

            Assert.Equal(json, JsonSerializer.Serialize(deserialized, opt));

            // Payload unsupported with strict options, but supported with default options
            json = """{"$type":"Derived","Name":null}""";

            deserialized = JsonSerializer.Deserialize<Base>(json, opt);
            Assert.IsType<Derived>(deserialized);

            Assert.Equal(json, JsonSerializer.Serialize(deserialized, opt));

            // Payload unsupported by both
            json = """{"$type":"Derived","Name":true}""";

            Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Base>(json, opt));
        }

        [JsonDerivedType(typeof(Derived), "Derived")]
        private class Base { }

        private class Derived : Base
        {
            public string Name { get; set; }
        }

        private class CustomConverterFactory : JsonConverterFactory
        {
            private readonly JsonSerializerOptions _baseOptions;

            private readonly JsonSerializerOptions _strictOptions;
            private readonly JsonSerializerOptions _defaultOptions;

            public CustomConverterFactory(JsonSerializerOptions baseOptions)
            {
                // Original options
                _baseOptions = baseOptions;

                // Customize by combining with original options if needed:
                _strictOptions = JsonSerializerOptions.Strict;
                _defaultOptions = JsonSerializerOptions.Default;
            }

            public override bool CanConvert(Type typeToConvert) => true;

            public override JsonConverter? CreateConverter(Type typeToConvert, JsonSerializerOptions options)
            {
                if (_baseOptions != options)
                    throw new JsonException("Options mismatch. Use the base options for converter creation.");

                return (JsonConverter)Activator.CreateInstance(typeof(CustomConverter<>).MakeGenericType(typeToConvert), this)!;
            }

            internal class CustomConverter<T> : JsonConverter<T>
            {
                private readonly CustomConverterFactory _parent;
                private readonly JsonConverter<T> _strictConverter;
                private readonly JsonConverter<T> _defaultConverter;

                public CustomConverter(CustomConverterFactory parent)
                {
                    _parent = parent;
                    _strictConverter = (JsonConverter<T>)parent._strictOptions.GetConverter(typeof(T));
                    _defaultConverter = (JsonConverter<T>)parent._defaultOptions.GetConverter(typeof(T));
                }

                public override bool CanHaveMetadata => _defaultConverter.CanHaveMetadata;

                public override T? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
                {
                    Utf8JsonReader cloned = reader;

                    try
                    {
                        T? ret = _strictConverter.Read(ref cloned, typeToConvert, _parent._strictOptions);
                        reader = cloned;
                        return ret;
                    }
                    catch (JsonException)
                    {
                        return _defaultConverter.Read(ref reader, typeToConvert, _parent._defaultOptions);
                    }
                }

                public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
                {
                    ArrayBufferWriter<byte> temp = new ArrayBufferWriter<byte>();

                    using (Utf8JsonWriter tempWriter = new Utf8JsonWriter(temp, writer.Options))
                    {
                        try
                        {
                            _strictConverter.Write(tempWriter, value, _parent._strictOptions);
                            tempWriter.Flush();
                            writer.WriteRawValue(temp.WrittenSpan, skipInputValidation: true);
                            return;
                        }
                        catch (JsonException)
                        {
                            _defaultConverter.Write(writer, value, _parent._defaultOptions);
                            return;
                        }
                    }

                    throw new NotImplementedException();
                }
            }
        }
    }
}
