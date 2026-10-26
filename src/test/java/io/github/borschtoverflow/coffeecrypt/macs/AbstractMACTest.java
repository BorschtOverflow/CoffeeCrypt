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

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

import io.github.borschtoverflow.coffeecrypt.AbstractTest;

abstract class AbstractMACTest extends AbstractTest
{
    abstract MAC getMAC();

    abstract String getHelloWorldMac();
    abstract String getLargeStringInputMac();
    abstract String getLargeStringInputAsMacKey();
    abstract String getMacForLargeTextFile();

    @Test
    void testNullInput()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class,
                () -> getMAC().generate((byte[]) null, new byte[0]));

        final String exceptionMessage = exception.getMessage();

        assertEquals("input is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testNullFile()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class,
                () -> getMAC().generate((Path) null, new byte[0]));

        final String exceptionMessage = exception.getMessage();

        assertEquals("file is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testNullKey()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class,
                () -> getMAC().generate(new byte[0], null));

        final String exceptionMessage = exception.getMessage();

        assertEquals("key is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testEmptyInput()
    {
        final byte[] emptyInput = new byte[0];
        final byte[] key        = {1, 2, 3};

        assertDoesNotThrow(() ->
        {
            final byte[] mac = getMAC().generate(emptyInput, key);
            assertNotNull(mac);
        });
    }

    @Test
    void testEmptyKey()
    {
        final byte[] emptyKey = new byte[0];
        final byte[] input    = {1, 2, 3};

        assertDoesNotThrow(() ->
        {
            final byte[] mac = getMAC().generate(input, emptyKey);
            assertNotNull(mac);
        });
    }

    @Test
    void testHelloWorld()
    {
        final byte[] input = "Hello, World!".getBytes();
        final byte[] key   = "Some-Secret-Key".getBytes();

        final byte[] output = getMAC().generate(input, key);

        final String expectedResult    = getHelloWorldMac();
        final String outputAsHexString = HexFormat.of().formatHex(output);

        assertEquals(expectedResult, outputAsHexString);
    }

    /// Must produce the same result given the same input
    @Test
    void testDeterminism()
    {
        final byte[] input = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        final byte[] key   = "Some-Secret-Key".getBytes(StandardCharsets.UTF_8);

        final byte[] output1 = getMAC().generate(input, key);
        final byte[] output2 = getMAC().generate(input, key);
        final byte[] output3 = getMAC().generate(input, key);

        assertArrayEquals(output1, output2);
        assertArrayEquals(output2, output3);
        assertArrayEquals(output3, output1);
    }

    @Test
    void testDifferentInstances()
    {
        final byte[] input = "some input".getBytes(StandardCharsets.UTF_8);
        final byte[] key   = "some key".getBytes(StandardCharsets.UTF_8);

        final MAC mac1 = getMAC();
        final MAC mac2 = getMAC();

        final byte[] output0 = getMAC().generate(input, key);
        final byte[] output1 = mac1.generate(input, key);
        final byte[] output2 = mac2.generate(input, key);

        assertArrayEquals(output0, output1);
        assertArrayEquals(output1, output2);
        assertArrayEquals(output2, output0);
    }

    @Test
    void testSlightlyDifferentInputs()
    {
        final byte[] input1 = {0};
        final byte[] input2 = {1};

        final byte[] key = {1};

        final byte[] mac1 = getMAC().generate(input1, key);
        final byte[] mac2 = getMAC().generate(input2, key);

        assertFalse(Arrays.equals(mac1, mac2));
    }

    @Test
    void testLargeStringInput()
    {
        final String largeInput = getLargeString();
        final String key        = "some-key";

        final byte[] inputAsBytes = largeInput.getBytes();
        final byte[] keyAsBytes   = key.getBytes();

        final byte[] output = getMAC().generate(inputAsBytes, keyAsBytes);

        final String expectedResult    = getLargeStringInputMac();
        final String outputAsHexString = HexFormat.of().formatHex(output);

        assertEquals(expectedResult, outputAsHexString);
    }

    @Test
    void testLargeStringInputAsKey()
    {
        final String largeKey = getLargeString();
        final String input    = "some-input";

        final byte[] largeKeyAsBytes = largeKey.getBytes();
        final byte[] inputAsBytes    = input.getBytes();

        final byte[] output = getMAC().generate(inputAsBytes, largeKeyAsBytes);

        final String expectedResult    = getLargeStringInputAsMacKey();
        final String outputAsHexString = HexFormat.of().formatHex(output);

        assertEquals(expectedResult, outputAsHexString);
    }

    @Test
    void testMacGenerationForLargeTextFile() throws IOException
    {
        final Path file = getLargeTextFilePath();

        final byte[] key = "some-key".getBytes();

        try
        {
            final byte[] output = getMAC().generate(file, key);

            final String outputAsHex    = HexFormat.of().formatHex(output);
            final String expectedOutput = getMacForLargeTextFile();

            assertEquals(expectedOutput, outputAsHex);
        }

        catch (IOException _)
        {
            fail(String.format("ERROR: couldn't open %s file", file));
        }
    }

    @Test
    void testMacVerificationForLargeTextFile() throws IOException
    {
        final byte[] validMac = HexFormat.of().parseHex(getMacForLargeTextFile());

        final Path inputFile = getLargeTextFilePath();
        final byte[] key     = "some-key".getBytes();

        assertTrue(getMAC().isValid(inputFile, key, validMac));
    }

    @Test
    void testMacCreationForNonExistentFile()
    {
        final Path nonExistentFile = Paths.get("dlhksdasdlkahdas");

        assertThrows(IOException.class, () -> getMAC().generate(nonExistentFile, new byte[0]));
    }

    @Test
    void testMacVerificationForInput()
    {
        final byte[] validMac = HexFormat.of().parseHex(getHelloWorldMac());

        final byte[] input = "Hello, World!".getBytes();
        final byte[] key   = "Some-Secret-Key".getBytes();

        assertTrue(getMAC().isValid(input, key, validMac));
    }

    @Test
    void testInvalidMacAsInput()
    {
        final byte[] invalidMac = {0};

        final byte[] input = "Hello, World!".getBytes();
        final byte[] key   = "Some-Secret-Key".getBytes();

        assertFalse(getMAC().isValid(input, key, invalidMac));
    }

    @Test
    void testInvalidMacAsInput2() throws IOException
    {
        final byte[] invalidMac = {0};

        final Path inputFile = Files.createTempFile("dummy-file", ".txt");
        final byte[] key     = "some-key".getBytes();

        assertFalse(getMAC().isValid(inputFile, key, invalidMac));
    }

    @Test
    void testVerifyMacWithNonExistingFile()
    {
        final Path nonExistingFile = Paths.get("dlasdhjlkasjd/dkajhsdkjahsd");

        assertThrows(IOException.class, () -> getMAC().isValid(nonExistingFile, new byte[0], new byte[0]));
    }
}
