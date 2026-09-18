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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

public final class SanitizerTest
{
    @Test
    void testOneDimCharArrayThrowsException()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            Sanitizer.sanitizeArray((char[]) null);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("array is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testOneDimByteArrayThrowsException()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            Sanitizer.sanitizeArray((byte[]) null);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("array is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testTwoDimCharArrayThrowsException()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            Sanitizer.sanitizeArray((char[][]) null);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("array is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testTwoDimByteArrayThrowsException()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            Sanitizer.sanitizeArray((byte[][]) null);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("array is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testOneDimCharArraySanitizer()
    {
        char[] array = {'s', 'e', 'c', 'r', 'e', 't'};

        final char[] expectedResult = {'\0', '\0', '\0', '\0', '\0', '\0'};

        Sanitizer.sanitizeArray(array);

        assertArrayEquals(expectedResult, array);
    }

    @Test
    void testOneDimByteArraySanitizer()
    {
        byte[] array = {1, 2, 3, 4, 5, 6};

        final byte[] expectedResult = {0, 0, 0, 0, 0, 0};

        Sanitizer.sanitizeArray(array);

        assertArrayEquals(expectedResult, array);
    }

    @Test
    void testTwoDimCharArraySanitizer()
    {
        char[][] array = {{'s', 'e', 'c', 'r', 'e', 't'}, {'d', 'a', 't', 'a'},};

        final char[][] expectedResult = {{'\0', '\0', '\0', '\0', '\0', '\0'}, {'\0', '\0', '\0', '\0'},};

        Sanitizer.sanitizeArray(array);

        assertArrayEquals(expectedResult, array);
    }

    @Test
    void testTwoDimByteArraySanitizer()
    {
        byte[][] array = {{1, 2, 3, 4, 5, 6}, {7, 8, 9, 0},};

        final byte[][] expectedResult = {{0, 0, 0, 0, 0, 0}, {0, 0, 0, 0},};

        Sanitizer.sanitizeArray(array);

        assertArrayEquals(expectedResult, array);
    }
}
