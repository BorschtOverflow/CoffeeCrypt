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

package utils;

import java.util.Arrays;

import io.github.borschtoverflow.coffeecrypt.utils.Sanitizer;

public final class SanitizerExample
{
    public static void main(String[] args)
    {
        char[] sensitiveData = {'p', '@', '3', '3', 'w', '0', 'r', 'd', '!'};

        Sanitizer.sanitizeArray(sensitiveData);

        System.out.println(Arrays.toString(sensitiveData));
    }
}
