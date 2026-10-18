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

/// @since v0.4.0
public final class SHA3_224 extends AbstractSHA3 implements HashFunction
{
    @Override
    protected boolean isSHAKE()
    {
        return false;
    }

    @Override
    public int getBlockSizeInBytes()
    {
        return 144;
    }

    @Override
    protected int getOutputLengthInBytes()
    {
        return 28; // 224 / 8 = 28
    }

    /// Hashes data using the **`SHA3-224`** algorithm
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA3_224();
    ///
    /// final byte[] input  = "Hello, World!".getBytes();
    /// final byte[] output = hashFunction.hashData(input);
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

    /// Hashes data in the file using the **`SHA3-224`** algorithm
    ///
    /// It can process large files by splitting the data into small fixed-size chunks
    ///
    /// ```java
    /// HashFunction hashFunction = new SHA3_224();
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
