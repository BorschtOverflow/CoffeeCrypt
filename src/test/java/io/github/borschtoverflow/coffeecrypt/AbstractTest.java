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

package io.github.borschtoverflow.coffeecrypt;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractTest
{
    @TempDir
    Path tempDirectory;

    private Path largeTextFile;

    private final static String loremIpsumParagraph = "Lorem ipsum dolor sit amet consectetur adipiscing elit. Quisque faucibus ex sapien vitae pellentesque sem placerat. In id cursus mi pretium tellus duis convallis. Tempus leo eu aenean sed diam urna tempor. Pulvinar vivamus fringilla lacus nec metus bibendum egestas. Iaculis massa nisl malesuada lacinia integer nunc posuere. Ut hendrerit semper vel class aptent taciti sociosqu. Ad litora torquent per conubia nostra inceptos himenaeos.";

    protected String getLargeString()
    {
        return loremIpsumParagraph.repeat(100);
    }

    protected Path generateLargeTextFile() throws IOException
    {
        if (largeTextFile != null && Files.exists(largeTextFile))
        {
            return largeTextFile;
        }

        largeTextFile = tempDirectory.resolve("large-input-file.txt");

        final int size = Integer.MAX_VALUE;

        try (var writer = Files.newBufferedWriter(largeTextFile))
        {
            long written = 0;

            while (written < size)
            {
                int remaining = (int) Math.min(loremIpsumParagraph.length(), size - written);

                writer.write(loremIpsumParagraph, 0, remaining);
                written += remaining;
            }
        }

        return largeTextFile;
    }
}
