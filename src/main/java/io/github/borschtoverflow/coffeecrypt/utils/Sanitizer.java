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

package io.github.borschtoverflow.coffeecrypt.utils;

import java.util.Arrays;
import lombok.NonNull;

/// Contains methods for clearing sensitive information from arrays
///
/// @since v0.0.1
public final class Sanitizer
{
    private Sanitizer()
    {
    }

    /// Sets all elements of a character array to **`\0`**
    ///
    /// @param array An array to sanitize
    ///
    /// @throws IllegalArgumentException if **`array`** is null
    public static void sanitizeArray(@NonNull char[] array)
    {
        Arrays.fill(array, '\0');
    }

    /// Sets all elements of a byte array to **`0`**
    ///
    /// @param array An array to sanitize
    ///
    /// @throws IllegalArgumentException if **`array`** is null
    public static void sanitizeArray(@NonNull byte[] array)
    {
        Arrays.fill(array, (byte) 0);
    }

    /// Sets all elements of a 2D character array to **`\0`**
    ///
    /// @param array An array to sanitize
    ///
    /// @throws IllegalArgumentException if **`array`** is null
    public static void sanitizeArray(@NonNull char[][] array)
    {
        for (char[] row : array)
        {
            Arrays.fill(row, '\0');
        }
    }

    /// Sets all elements of a 2D byte array to **`0`**
    ///
    /// @param array An array to sanitize
    ///
    /// @throws IllegalArgumentException if **`array`** is null
    public static void sanitizeArray(@NonNull byte[][] array)
    {
        for (byte[] row : array)
        {
            Arrays.fill(row, (byte) 0);
        }
    }
}
