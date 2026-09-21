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
public final class SHA2_224 extends AbstractSHA2Int
{
    /// The initial hash values for SHA2-224
    // spotless:off
    private static final int[] IV =
    {
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4,
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
        return 28; // 224 / 8 = 28
    }

    @Override
    public int getBlockSizeInBytes()
    {
        return super.getBlockSizeInBytes();
    }

    /// Hashes data using the **`SHA2-224`** algorithm
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_224();
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

    /// Hashes data in the file using the **`SHA2-224`** algorithm
    ///
    /// It can process large files by splitting the data into small fixed-size chunks
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_224();
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
