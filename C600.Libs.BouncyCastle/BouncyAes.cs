using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace C600.Libs.BouncyCastle
{
	public class BouncyAes
	{
		private const string Algorithm = "AES/CBC/PKCS7PADDING";

		private const byte AesIvSize = 16;
		private const byte CbcTagSize = 16;

		private const CipherMode CipherMode = System.Security.Cryptography.CipherMode.CBC;

		public string Encrypt(string plainText, byte[] key)
		{
			var iv = GetInitializationVector();
			var keyParameters = CreateKeyParameters(key, iv, CbcTagSize * 8);
			var cipher = GetInitializedAesCipher(keyParameters);
			var plainTextData = Encoding.UTF8.GetBytes(plainText);
			var cipherText = cipher.DoFinal(plainTextData);

			Array.Clear(plainTextData, 0, plainTextData.Length);

			return PackCipherData(cipherText, iv);
		}

		public string Decrypt(string cipherText, byte[] key)
		{
			var unpackedCipherData = UnpackCipherData(cipherText);
			var keyParameters = CreateKeyParameters(key, unpackedCipherData.Iv, unpackedCipherData.TagSize * 8);
			var cipher = GetInitializedAesCipher(keyParameters);
			var decryptedData = cipher.DoFinal(unpackedCipherData.EncryptedBytes);
			var decryptedString = Encoding.UTF8.GetString(decryptedData);

			Array.Clear(decryptedData, 0, decryptedData.Length);

			return decryptedString;
		}

		private static ICipherParameters CreateKeyParameters(byte[] key, byte[] iv, int macSize)
		{
			var keyParameter = new KeyParameter(key);
			if (CipherMode == CipherMode.CBC)
			{
				return new ParametersWithIV(keyParameter, iv);
			}

			throw new Exception("Unsupported cipher mode");
		}

		private static string PackCipherData(byte[] encryptedBytes, byte[] iv)
		{
			var dataSize = encryptedBytes.Length + iv.Length + 1;
			var index = 0;
			var data = new byte[dataSize];
			data[index] = AesIvSize;
			index += 1;
			Array.Copy(iv, 0, data, index, iv.Length);
			index += iv.Length;
			Array.Copy(encryptedBytes, 0, data, index, encryptedBytes.Length);

			return Convert.ToBase64String(data);
		}

		private static UnpackedCipherData UnpackCipherData(string cipherText)
		{
			var index = 0;
			var cipherData = Convert.FromBase64String(cipherText);
			var ivSize = cipherData[index];
			index += 1;

			var iv = new byte[ivSize];
			Array.Copy(cipherData, index, iv, 0, ivSize);
			index += ivSize;

			var encryptedBytes = new byte[cipherData.Length - index];
			Array.Copy(cipherData, index, encryptedBytes, 0, encryptedBytes.Length);
			return new UnpackedCipherData()
			{
				EncryptedBytes = encryptedBytes,
				Iv = iv,
				TagSize = 0
			};
		}

		private struct UnpackedCipherData
		{
			public byte[] EncryptedBytes;
			public byte[] Iv;
			public byte TagSize;
		}

		private static IBufferedCipher GetInitializedAesCipher(ICipherParameters keyParameters)
		{
			var cipher = CipherUtilities.GetCipher(Algorithm);
			cipher.Init(false, keyParameters);
			return cipher;
		}

		private static byte[] GetInitializationVector()
		{
			var random = new SecureRandom();
			return random.GenerateSeed(AesIvSize);
		}
	}

}
