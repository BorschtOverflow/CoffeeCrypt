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
public final class SHA2_384 extends AbstractSHA2Long
{
    /// The Initial Values for **`SHA2-384`**
    ///
    /// These words were obtained by taking the first
    /// sixty-four bits of the fractional parts of the
    /// squareroots of the ninth through sixteenth prime numbers
    ///
    // spotless:off
    private static final long[] IV =
    {
        0xcbbb9d5dc1059ed8L,
        0x629a292a367cd507L,
        0x9159015a3070dd17L,
        0x152fecd8f70e5939L,
        0x67332667ffc00b31L,
        0x8eb44a8768581511L,
        0xdb0c2e0d64f98fa7L,
        0x47b5481dbefa4fa4L,
    };
    //spotless:on

    @Override
    protected long[] getIV()
    {
        return IV;
    }

    @Override
    protected int getHashLengthInBytes()
    {
        return 48; // 384 / 8 = 48
    }

    @Override
    public int getBlockSizeInBytes()
    {
        return super.getBlockSizeInBytes();
    }

    /// Hashes data using the **`SHA2-384`** algorithm
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_384();
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

    /// Hashes data in the file using the **`SHA2-384`** algorithm
    ///
    /// It can process large files by splitting the data into small fixed-size chunks
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_384();
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
