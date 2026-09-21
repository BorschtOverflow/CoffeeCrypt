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
public final class SHA2_512t256 extends AbstractSHA2Long
{
    /// The Initial Values for **`SHA2-512/256`**
    ///
    /// These words were obtained by executing the
    /// SHA-512/t IV Generation Function with t = 256.
    ///
    // spotless:off
    private static final long[] IV =
    {
        0x22312194FC2BF72CL,
        0x9F555FA3C84C64C2L,
        0x2393B86B6F53B151L,
        0x963877195940EABDL,
        0x96283EE2A88EFFE3L,
        0xBE5E1E2553863992L,
        0x2B0199FC2C85B8AAL,
        0x0EB72DDC81C52CA2L,
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
        return 32; // 256 / 8 = 32
    }

    @Override
    public int getBlockSizeInBytes()
    {
        return super.getBlockSizeInBytes();
    }

    /// Hashes data using the **`SHA2-512/256`** algorithm
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_512t256();
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

    /// Hashes data in the file using the **`SHA2-512/256`** algorithm
    ///
    /// It can process large files by splitting the data into small fixed-size chunks
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA2_512t256();
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
    /// @throws IOException if **`file`** can't be opened || doesn't exist
    @Override
    public byte[] hashFile(@NonNull Path file) throws IOException
    {
        return super.hashFile(file);
    }
}
