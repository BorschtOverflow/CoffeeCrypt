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

/// FIPS 202 implementation of SHAKE128
/// @since v0.4.0
public final class SHAKE128 extends AbstractSHA3 implements XOF
{
    @Override
    protected boolean isSHAKE()
    {
        return true;
    }

    @Override
    public int getBlockSizeInBytes()
    {
        return 168;
    }

    @Override
    protected int getOutputLengthInBytes()
    {
        return 32; // Default 256-bit output length
    }

    /// Hashes data using the **`SHAKE128`** algorithm
    ///
    /// ```java
    /// XOF xof = new SHAKE128();
    ///
    /// final long outputLength = 37;
    /// final byte[] input  = "Hello, World!".getBytes();
    /// final byte[] output = xof.hashData(input, outputLength);
    /// ```
    ///
    /// @param input An array of bytes to hash
    /// @param hashLengthInBytes The length of an output hash in bytes
    ///
    /// @throws IllegalArgumentException if **`input`** is **`null`**
    @Override
    public byte[] hashData(@NonNull byte[] input, long hashLengthInBytes)
    {
        if (hashLengthInBytes <= 0)
        {
            throw new IllegalArgumentException("ERROR: hashLengthInBytes cannot be 0 or less!");
        }

        return super.hashData(input, hashLengthInBytes);
    }

    /// Hashes data in the file using the **`SHAKE128`** algorithm
    ///
    /// It can process large files by splitting the data into small fixed-size chunks
    ///
    /// ```java
    /// XOF xof = new SHAKE128()
    ///
    /// final long outputLength = 96;
    /// final Path inputFile = Paths.get("some-file");
    ///
    /// try
    /// {
    ///    final byte[] output = xof.hashFile(inputFile, outputLength);
    /// }
    ///
    /// catch(IOException exception)
    /// {
    ///     System.err.printf("ERROR: failed to hash %s!\n%s", inputFile.toString(), exception.getMessage());
    /// }
    /// ```
    ///
    /// @param file Path to the file
    /// @param hashLengthInBytes The length of an output hash in bytes
    ///
    /// @throws IllegalArgumentException if **`file`** is **`null`** or if **`hashLengthInBytes`** is 0 or less
    /// @throws IOException if **`file`** can't be opened or doesn't exist
    @Override
    public byte[] hashFile(@NonNull Path file, long hashLengthInBytes) throws IOException
    {
        if (hashLengthInBytes <= 0)
        {
            throw new IllegalArgumentException("ERROR: hashLengthInBytes cannot be 0 or less!");
        }

        return super.hashFile(file, hashLengthInBytes);
    }
}
