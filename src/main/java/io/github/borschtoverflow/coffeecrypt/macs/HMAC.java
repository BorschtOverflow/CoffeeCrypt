/* Copyright (C) 2026 BorschtOverflow
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>,
 */

package io.github.borschtoverflow.coffeecrypt.macs;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Files;
import java.security.MessageDigest;
import lombok.NonNull;

import io.github.borschtoverflow.coffeecrypt.hashing.HashFunction;

/// Hash based Message authentication Code
/// @since v0.3.0
public final class HMAC implements MAC
{
    private final HashFunction hashFunction;

    private static final byte IPAD = 0x36; // Inner padding
    private static final byte OPAD = 0x5c; // Outer padding

    /// @throws IllegalArgumentException if **`hashFunction`** is **`null`**
    public HMAC(@NonNull HashFunction hashFunction)
    {
        this.hashFunction = hashFunction;
    }

    private byte[] prepareKey(byte[] key, int blockSizeInBytes)
    {
        byte[] result = new byte[blockSizeInBytes];

        if (key.length > blockSizeInBytes)
        {
            final byte[] hashedKey = hashFunction.hashData(key);
            System.arraycopy(hashedKey, 0, result, 0, Math.min(hashedKey.length, blockSizeInBytes));
        }

        else
        {
            System.arraycopy(key, 0, result, 0, key.length);
        }

        return result;
    }

    private byte[] xorInputWithPad(byte[] input, byte pad)
    {
        byte[] result = new byte[input.length];

        for (int i = 0; i < result.length; i++)
        {
            result[i] = (byte) (input[i] ^ pad);
        }

        return result;
    }

    private byte[] concatinate(byte[] firstPart, byte[] secondPart)
    {
        byte[] result = new byte[firstPart.length + secondPart.length];

        System.arraycopy(firstPart, 0, result, 0, firstPart.length);
        System.arraycopy(secondPart, 0, result, firstPart.length, secondPart.length);

        return result;
    }

    // Create a temporary file containing [ipadKey + fileContents]
    // so hashFunction.hashFile() can stream the entire inner input
    private byte[] hashFileWithPrefix(byte[] prefix, Path file) throws IOException
    {
        final Path tempFile = Files.createTempFile("hmac_inner_", ".tmp");

        try
        {
            try (OutputStream out = Files.newOutputStream(tempFile))
            {
                out.write(prefix);
                Files.copy(file, out);
            }

            return hashFunction.hashFile(tempFile);
        }

        finally
        {
            Files.deleteIfExists(tempFile);
        }
    }

    /// Generates hash based message authentication code
    ///
    /// ```java
    /// MAC sha512Hmac = new HMAC(new SHA2_512); // Can be any hash function
    ///                                          // That implements the HashFunction
    ///                                          // interface
    ///
    /// final byte[] input = "some-input".getBytes();
    /// final byte[] key   = "some-key".getBytes();
    ///
    /// final byte[] mac = sha512Hmac.generate(input, key);
    /// ```
    ///
    /// @param input An array of bytes to authentificate
    /// @param key A secret key
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    ///
    /// @return A message authentication code
    @Override
    public byte[] generate(@NonNull byte[] input, @NonNull byte[] key)
    {
        final int blockSizeInBytes = hashFunction.getBlockSizeInBytes();

        final byte[] preparedKey = prepareKey(key, blockSizeInBytes);

        final byte[] ipadKey = xorInputWithPad(preparedKey, IPAD);
        final byte[] opadKey = xorInputWithPad(preparedKey, OPAD);

        final byte[] innnerInput = concatinate(ipadKey, input);
        final byte[] innerHash   = hashFunction.hashData(innnerInput);
        final byte[] outerInput  = concatinate(opadKey, innerHash);

        return hashFunction.hashData(outerInput);
    }

    /// Generates hash based message authentication code
    ///
    /// ```java
    /// MAC sha512Hmac = new HMAC(new SHA2_512); // Can be any hash function
    ///                                          // That implements the HashFunction
    ///                                          // interface
    ///
    /// final Path   inputFile = Paths.get("some-file");
    /// final byte[] key       = "some-key".getBytes();
    ///
    /// try
    /// {
    ///     final byte[] mac = sha512Hmac.generate(inputFile, key);
    /// }
    ///
    /// catch (IOException exception)
    /// {
    ///     System.err.printf("ERROR: failed to generate HMAC");
    /// }
    /// ```
    ///
    /// @param file Path to the file to authenticate
    /// @param key A secret key
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    /// @throws IOException              if **`file`** cannot be opened or doesn't exist
    ///
    /// @return A message authentication code
    @Override
    public byte[] generate(@NonNull Path file, @NonNull byte[] key) throws IOException
    {
        final int blockSizeInBytes = hashFunction.getBlockSizeInBytes();

        byte[] preparedKey = prepareKey(key, blockSizeInBytes);

        byte[] ipadKey = xorInputWithPad(preparedKey, IPAD);
        byte[] opadKey = xorInputWithPad(preparedKey, OPAD);

        byte[] innerHash  = hashFileWithPrefix(ipadKey, file);
        byte[] outerInput = concatinate(opadKey, innerHash);

        return hashFunction.hashData(outerInput);
    }

    /// Checks whether the hash based message authentication code is valid
    ///
    /// Uses constant time comparison to prevent timing attacks
    ///
    /// ```java
    /// MAC sha224Hmac = new HMAC(new SHA2_224);
    ///
    /// final byte[] input = "some-input".getBytes();
    /// final byte[] key   = "some-key".getBytes();
    /// final String mac   = "e447741ac59e8a197c17ffacbee45e508521ba21df73a9715828edf1";
    ///
    /// final byte[] macBytes = HexFormat.of().parseHex(mac);
    ///
    /// boolean isValid = sha224Hmac.isValid(input, key, macBytes);
    /// ```
    ///
    /// @param input An array of bytes that were used to generate a MAC
    /// @param key A secret key that was used to generate a MAC
    /// @param mac A message authentication code
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    ///
    /// @return A boolean
    @Override
    public boolean isValid(@NonNull byte[] input, @NonNull byte[] key, @NonNull byte[] mac)
    {
        return MessageDigest.isEqual(generate(input, key), mac);
    }

    /// Checks whether the hash based message authentication code is valid
    ///
    /// Uses constant time comparison to prevent timing attacks
    ///
    /// ```java
    /// MAC sha224Hmac = new HMAC(new SHA2_224);
    ///
    /// final Path fileInput = Paths.get("some-file");
    /// final byte[] key     = "some-key".getBytes();
    /// final String mac     = "e447741ac59e8a197c17ffacbee45e508521ba21df73a9715828edf1";
    ///
    /// final byte[] macBytes = HexFormat.of().parseHex(mac);
    ///
    /// try
    /// {
    ///     boolean isValid = sha224Hmac.isValid(fileInput, key, macBytes);
    /// }
    ///
    /// catch (IOException exception)
    /// {
    ///     System.err.printf("ERROR: failed to verify HMAC");
    /// }
    /// ```
    ///
    /// @param file Path to the file that was used to generate a MAC
    /// @param key A secret key that was used to generate a MAC
    /// @param mac A message authentication code
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    ///
    /// @return A boolean
    @Override
    public boolean isValid(@NonNull Path file, @NonNull byte[] key, @NonNull byte[] mac) throws IOException
    {
        return MessageDigest.isEqual(generate(file, key), mac);
    }
}
