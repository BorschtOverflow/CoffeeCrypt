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
import java.nio.file.Path;
import lombok.NonNull;

/// Interface for message authentication codes
///
/// @since v0.3.0
public interface MAC
{
    /// Generates message authentication code
    ///
    /// @param input An array of bytes to authenticate
    /// @param key A secret key
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    ///
    /// @return A message authentication code
    byte[] generate(@NonNull byte[] input, @NonNull byte[] key);

    /// Generates message authentication code
    ///
    /// @param file Path to the file to authenticate
    /// @param key A secret key
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    /// @throws IOException              if **`file`** cannot be opened or doesn't exist
    ///
    /// @return A message authentication code
    byte[] generate(@NonNull Path file, @NonNull byte[] key) throws IOException;

    /// Checks whether the message authentication code is valid
    ///
    /// Uses constant time comparison to prevent timing attacks
    ///
    /// @param input An array of bytes that were used to generate a MAC
    /// @param key A secret key that was used to generate a MAC
    /// @param mac A message authentication code
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    ///
    /// @return A boolean
    boolean isValid(@NonNull byte[] input, @NonNull byte[] key, @NonNull byte[] mac);

    /// Checks whether the message authentication code is valid
    ///
    /// Uses constant time comparison to prevent timing attacks
    ///
    /// @param file Path to the file that was used to generate a MAC
    /// @param key A secret key that was used to generate a MAC
    /// @param mac A message authentication code
    ///
    /// @throws IllegalArgumentException if at least one of the parameters is **`null`**
    /// @throws IOException              if **`file`** cannot be opened or doesn't exist
    ///
    /// @return A boolean
    boolean isValid(@NonNull Path file, @NonNull byte[] key, @NonNull byte[] mac) throws IOException;
}
