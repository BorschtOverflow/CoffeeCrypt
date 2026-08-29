/*  Copyright (C) 2026 BorschtOverflow
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package io.github.borschtoverflow.coffeecrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

public final class MainTest
{
    @Test
    void testMainMethod()
    {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        System.setOut(new PrintStream(byteArrayOutputStream));

        Main.main(new String[]{});

        final String actualOutput = byteArrayOutputStream.toString().trim();

        assertEquals("Hello, World!", actualOutput);
    }
}
