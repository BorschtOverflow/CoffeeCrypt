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

package hashing;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HexFormat;

import io.github.borschtoverflow.coffeecrypt.hashing.HashFunction;
import io.github.borschtoverflow.coffeecrypt.hashing.SHA2_512t224;

public final class SHA2_512t224Example
{
    public static void main(String[] args)
    {
        HashFunction hashFunction = new SHA2_512t224();

        final String input        = "Hello, World!";
        final byte[] inputAsBytes = input.getBytes();

        final byte[] output = hashFunction.hashData(inputAsBytes);

        final String outputInHex = HexFormat.of().formatHex(output);

        System.out.printf("SHA2-512/224(\"%s\") = \"%s\"\n", input, outputInHex);

        final Path inputFile = Paths.get("gradle/wrapper/gradle-wrapper.jar");

        try
        {
            final byte[] fileHash = hashFunction.hashFile(inputFile);

            final String fileHashInHex = HexFormat.of().formatHex(fileHash);

            System.out.printf("SHA2-512/224(%s) = \"%s\"", inputFile.toString(), fileHashInHex);
        }

        catch (IOException exception)
        {
            System.err.printf("ERROR: failed to hash %s!\n%s", inputFile.toString(), exception.getMessage());
        }
    }
}
