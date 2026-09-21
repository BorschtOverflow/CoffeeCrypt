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

package io.github.borschtoverflow.coffeecrypt.hashing;

import java.io.IOException;
import java.nio.file.Path;
import lombok.NonNull;

/// @since v0.2.0
public final class SHA2_256 extends AbstractSHA2Int
{
    /// The initial hash values for **`SHA2-256`**
    ///
    /// These words were obtained by taking the first
    /// thirty-two bits of the fractional parts of the
    /// square roots of the first eight prime numbers.
    ///
    // spotless:off
    private static final int[] IV =
    {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };
    // spotless:on

    @Override
    protected int[] getIV()
    {
        return IV;
    }

    @Override
    protected int getHashLengthInBytes()
    {
        return 32; // 256 / 8 = 32
    }

    @Override
    public int getBlockSizeInBytes()
    {
        return super.getBlockSizeInBytes();
    }

    /// Hashes data using the **`SHA2-256`** algorithm
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_256();
    ///
    /// final byte[] input  = "Hello, World!".getBytes();
    /// final byte[] output = hashFunction.hashData();
    /// ```
    ///
    /// @param input An array of bytes to hash
    ///
    /// @throws IllegalArgumentException if **`input`** is **`null`**
    @Override
    public byte[] hashData(@NonNull byte[] input)
    {
        return super.hashData(input);
    }

    /// Hashes data in the file using the **`SHA2-256`** algorithm
    ///
    /// It can process large files by splitting the data into small fixed-size chunks
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_256();
    ///
    /// final Path inputFile = Paths.get("some-file");
    ///
    /// try
    /// {
    ///    final byte[] output = hashFunction.hashFile(inputFile);
    /// }
    ///
    /// catch(IOException exception)
    /// {
    ///     System.err.printf("ERROR: failed to hash %s!\n%s", inputFile.toString(), exception.getMessage());
    /// }
    /// ```
    ///
    /// @param file Path to the file
    ///
    /// @throws IllegalArgumentException if **`file`** is **`null`**
    /// @throws IOException              if **`file`** can't be opened || doesn't exist
    @Override
    public byte[] hashFile(@NonNull Path file) throws IOException
    {
        return super.hashFile(file);
    }
}
