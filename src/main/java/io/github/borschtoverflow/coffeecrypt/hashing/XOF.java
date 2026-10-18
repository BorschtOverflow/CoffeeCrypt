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

/// eXtendable Output Function
///
/// @since v0.4.0
public interface XOF
{
    /// Generates a custom length hash from input data
    ///
    /// @param data An array of bytes
    /// @param hashLengthInBytes An output hash length in bytes
    ///
    /// @return A hash as an array of bytes
    ///
    /// @throws IllegalArgumentException If **`data`** is **`null`** or if **`hashLengthInBytes`** is 0 or less
    byte[] hashData(@NonNull byte[] data, long hashLengthInBytes);

    /// Generates a custom length hash from input file
    ///
    /// @param file Path to the file
    /// @param hashLengthInBytes An output hash length in bytes
    ///
    /// @return A hash as an array of bytes
    ///
    /// @throws IllegalArgumentException If **`file`** is **`null`** or if **`hashLengthInBytes`** is 0 or less
    /// @throws IOException If **`file`** cannot be opened or doesn't exist
    byte[] hashFile(@NonNull Path file, long hashLengthInBytes) throws IOException;

    /// Returns the internal block size in bytes
    int getBlockSizeInBytes();
}
