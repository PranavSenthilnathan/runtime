// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Text.Encodings.Web;
using Newtonsoft.Json;
using Xunit;

namespace System.Text.Json.Serialization.Tests
{
    public static partial class ValueTests
    {
        [Fact]
        public static void WriteStringWithRelaxedEscaper()
        {
            string inputString = ">><++>>>\">>\\>>&>>>\u6f22\u5B57>>>"; // Non-ASCII text should remain unescaped. \u6f22 = \u6C49, \u5B57 = \u5B57

            string actual = JsonSerializer.Serialize(inputString, new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            string expected = "\">><++>>>\\\">>\\\\>>&>>>\u6f22\u5B57>>>\"";
            Assert.Equal(JsonConvert.SerializeObject(inputString), actual);
            Assert.Equal(expected, actual);
            Assert.NotEqual(expected, JsonSerializer.Serialize(inputString));
        }

        [Fact]
        public static void WritePrimitives()
        {
            {
                string json = JsonSerializer.Serialize(1);
                Assert.Equal("1", json);
            }

            {
                int? value = 1;
                string json = JsonSerializer.Serialize(value);
                Assert.Equal("1", json);
            }

            {
                int? value = null;
                string json = JsonSerializer.Serialize(value);
                Assert.Equal("null", json);
            }

            {
                string json = JsonSerializer.Serialize((string)null);
                Assert.Equal("null", json);
            }

            {
                Span<byte> json = JsonSerializer.SerializeToUtf8Bytes(1);
                Assert.Equal("1"u8.ToArray(), json.ToArray());
            }

            {
                string json = JsonSerializer.Serialize(long.MaxValue);
                Assert.Equal(long.MaxValue.ToString(), json);
            }

            {
                Span<byte> json = JsonSerializer.SerializeToUtf8Bytes(long.MaxValue);
                Assert.Equal(Encoding.UTF8.GetBytes(long.MaxValue.ToString()), json.ToArray());
            }

            {
                string json = JsonSerializer.Serialize("Hello");
                Assert.Equal(@"""Hello""", json);
            }

            {
                Span<byte> json = JsonSerializer.SerializeToUtf8Bytes("Hello");
                Assert.Equal(Encoding.UTF8.GetBytes(@"""Hello"""), json.ToArray());
            }

            {
                Uri uri = new Uri("https://domain/path");
                Assert.Equal(@"""https://domain/path""", JsonSerializer.Serialize(uri));
            }

            {
                Uri.TryCreate("~/path", UriKind.RelativeOrAbsolute, out Uri uri);
                Assert.Equal(@"""~/path""", JsonSerializer.Serialize(uri));
            }

            // The next two scenarios validate that we're NOT using Uri.ToString() for serializing Uri. The serializer
            // will escape backslashes and ampersands, but otherwise should be the same as the output of Uri.OriginalString.

            {
                // ToString would collapse the relative segment
                Uri uri = new Uri("http://a/b/../c");
                Assert.Equal(@"""http://a/b/../c""", JsonSerializer.Serialize(uri));
            }

            {
                // "%20" gets turned into a space by Uri.ToString()
                // https://coding.abel.nu/2014/10/beware-of-uri-tostring/
                Uri uri = new Uri("http://localhost?p1=Value&p2=A%20B%26p3%3DFooled!");
                Assert.Equal(@"""http://localhost?p1=Value\u0026p2=A%20B%26p3%3DFooled!""", JsonSerializer.Serialize(uri));
            }

            {
                Version version = new Version(1, 2);
                Assert.Equal(@"""1.2""", JsonSerializer.Serialize(version));
            }

            {
                Version version = new Version(1, 2, 3);
                Assert.Equal(@"""1.2.3""", JsonSerializer.Serialize(version));
            }

            {
                Version version = new Version(1, 2, 3, 4);
                Assert.Equal(@"""1.2.3.4""", JsonSerializer.Serialize(version));
            }

            {
                Version version = new Version(int.MaxValue, int.MaxValue);
                Assert.Equal(@"""2147483647.2147483647""", JsonSerializer.Serialize(version));
            }

            {
                Version version = new Version(int.MaxValue, int.MaxValue, int.MaxValue);
                Assert.Equal(@"""2147483647.2147483647.2147483647""", JsonSerializer.Serialize(version));
            }

            {
                Version version = new Version(int.MaxValue, int.MaxValue, int.MaxValue, int.MaxValue);
                Assert.Equal(@"""2147483647.2147483647.2147483647.2147483647""", JsonSerializer.Serialize(version));
            }
        }

        [Theory]
        [InlineData("1:59:59", "01:59:59")]
        [InlineData("23:59:59")]
        [InlineData("23:59:59.9", "23:59:59.9000000")]
        [InlineData("23:59:59.9999999")]
        [InlineData("1.23:59:59")]
        [InlineData("9999999.23:59:59.9999999")]
        [InlineData("-9999999.23:59:59.9999999")]
        [InlineData("10675199.02:48:05.4775807")] // TimeSpan.MaxValue
        [InlineData("-10675199.02:48:05.4775808")] // TimeSpan.MinValue
        public static void TimeSpan_Write_Success(string value, string? expectedValue = null)
        {
            TimeSpan ts = TimeSpan.Parse(value);
            string json = JsonSerializer.Serialize(ts);

            Assert.Equal($"\"{expectedValue ?? value}\"", json);
            Assert.Equal(json, JsonConvert.SerializeObject(ts));
        }

#if NET
        [Theory]
        [InlineData("1970-01-01")]
        [InlineData("2002-02-13")]
        [InlineData("2022-05-10")]
        [InlineData("0001-01-01")] // DateOnly.MinValue
        [InlineData("9999-12-31")] // DateOnly.MaxValue
        public static void DateOnly_Write_Success(string value)
        {
            DateOnly ts = DateOnly.Parse(value);
            string json = JsonSerializer.Serialize(ts);
            Assert.Equal($"\"{value}\"", json);
        }

        [Theory]
        [InlineData("1970-01-01")]
        [InlineData("2002-02-13")]
        [InlineData("2022-05-10")]
        [InlineData("0001-01-01")] // DateOnly.MinValue
        [InlineData("9999-12-31")] // DateOnly.MaxValue
        public static void DateOnly_WriteDictionaryKey_Success(string value)
        {
            var dict = new Dictionary<DateOnly, int> { [DateOnly.Parse(value)] = 0 };
            string json = JsonSerializer.Serialize(dict);
            Assert.Equal($@"{{""{value}"":0}}", json);
        }

        [Theory]
        [InlineData("1:59:59", "01:59:59")]
        [InlineData("23:59:59")]
        [InlineData("23:59:59.9", "23:59:59.9000000")]
        [InlineData("00:00:00")] // TimeOnly.MinValue
        [InlineData("23:59:59.9999999")] // TimeOnly.MaxValue
        public static void TimeOnly_Write_Success(string value, string? expectedValue = null)
        {
            TimeOnly ts = TimeOnly.Parse(value);
            string json = JsonSerializer.Serialize(ts);
            Assert.Equal($"\"{expectedValue ?? value}\"", json);
        }

        [Fact]
        public static void Int128_AsDictionaryKey_SerializesCorrectly()
        {
            // Regression test for https://github.com/dotnet/runtime/issues/116855
            var dict = new Dictionary<Int128, string>
            {
                [0] = "Zero",
                [1] = "One",
                [-1] = "MinusOne",
                [Int128.MaxValue] = "Max",
                [Int128.MinValue] = "Min"
            };

            string json = JsonSerializer.Serialize(dict);
            Assert.Equal("""{"0":"Zero","1":"One","-1":"MinusOne","170141183460469231731687303715884105727":"Max","-170141183460469231731687303715884105728":"Min"}""", json);
            
            var deserialized = JsonSerializer.Deserialize<Dictionary<Int128, string>>(json);
            Assert.Equal(dict, deserialized);
        }

        [Fact]
        public static void UInt128_AsDictionaryKey_SerializesCorrectly()
        {
            // Regression test for https://github.com/dotnet/runtime/issues/116855
            var dict = new Dictionary<UInt128, string>
            {
                [0] = "Zero", 
                [1] = "One",
                [UInt128.MaxValue] = "Max"
            };

            string json = JsonSerializer.Serialize(dict);
            Assert.Equal("""{"0":"Zero","1":"One","340282366920938463463374607431768211455":"Max"}""", json);
            
            var deserialized = JsonSerializer.Deserialize<Dictionary<UInt128, string>>(json);
            Assert.Equal(dict, deserialized);
        }
#endif
    }
}
