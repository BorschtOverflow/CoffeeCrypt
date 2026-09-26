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

package macs;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HexFormat;

import io.github.borschtoverflow.coffeecrypt.macs.HMAC;
import io.github.borschtoverflow.coffeecrypt.macs.MAC;
import io.github.borschtoverflow.coffeecrypt.hashing.SHA2_256;

public final class HMACExample
{
    public static void main(String[] args)
    {
        // -------------------- Generate MAC -------------------- \\
        MAC sha256Hmac = new HMAC(new SHA2_256()); // You can pass any hash function
                                                   // that implements the HashFunction
                                                   // interface

        final String input = "Hello, World!";
        final String key   = "Some-Secret!-Value";

        final byte[] inputAsBytes = input.getBytes();
        final byte[] keyAsBytes   = key.getBytes();

        final byte[] output = sha256Hmac.generate(inputAsBytes, keyAsBytes);

        final String outputInHex = HexFormat.of().formatHex(output);

        System.out.printf("HMAC-SHA2-256(\"%s\", \"%s\") = %s\n", input, key, outputInHex);

        // -------------------- Generate MAC from file -------------------- \\

        final Path inputFile = Paths.get("gradle/wrapper/gradle-wrapper.jar");

        final byte[] fileMac;

        try
        {
            fileMac = sha256Hmac.generate(inputFile, keyAsBytes);

            final String fileMacInHex = HexFormat.of().formatHex(fileMac);

            System.out.printf("HMAC-SHA2-256(%s, \"%s\") = %s\n", inputFile.toString(), key, fileMacInHex);
        }

        catch (IOException exception)
        {
            System.err.printf("ERROR: failed to generate HMAC for %s!\n%s", inputFile.toString(),
                    exception.getMessage());
        }

        // -------------------- Verify HMACs -------------------- \\

        final boolean isInputMacValid = sha256Hmac.isValid(inputAsBytes, keyAsBytes, output);

        if (isInputMacValid)
        {
            System.out.printf("%s is a valid HMAC for input:\"%s\" and key:\"%s\"\n", outputInHex, input, key);
        }

        else
        {
            System.out.printf("%s is not a valid HMAC for input:\"%s\" and key:\"%s\"\n", outputInHex, input, key);
        }
    }
}
