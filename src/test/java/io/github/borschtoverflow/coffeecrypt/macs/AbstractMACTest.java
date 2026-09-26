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
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

abstract class AbstractMACTest
{
    abstract MAC getMAC();

    abstract String getHelloWorldMac();
    abstract String getLargeInputMac();
    abstract String getMacForFile();

    private String getLargeString()
    {
        final StringBuilder largeString = new StringBuilder();

        final String loremIpsumParagraph = "Lorem ipsum dolor sit amet consectetur adipiscing elit. Quisque faucibus ex sapien vitae pellentesque sem placerat. In id cursus mi pretium tellus duis convallis. Tempus leo eu aenean sed diam urna tempor. Pulvinar vivamus fringilla lacus nec metus bibendum egestas. Iaculis massa nisl malesuada lacinia integer nunc posuere. Ut hendrerit semper vel class aptent taciti sociosqu. Ad litora torquent per conubia nostra inceptos himenaeos.";

        for (int i = 0; i < 100; i++)
        {
            largeString.append(loremIpsumParagraph);
        }

        return largeString.toString();
    }

    @Test
    void testNullInput()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            getMAC().generate((byte[]) null, new byte[0]);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("input is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testNullFile()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            getMAC().generate((Path) null, new byte[0]);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("file is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testNullKey()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            getMAC().generate(new byte[0], null);
        });

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
    void testLargeInput()
    {
        final String largeInput = getLargeString();
        final String key        = "some-key";

        final byte[] inputAsBytes = largeInput.getBytes();
        final byte[] keyAsBytes   = key.getBytes();

        final byte[] output = getMAC().generate(inputAsBytes, keyAsBytes);

        final String expectedResult    = getLargeInputMac();
        final String outputAsHexString = HexFormat.of().formatHex(output);

        assertEquals(expectedResult, outputAsHexString);
    }

    @Test
    void testMacGenerationForFile()
    {
        // Just needed a file that would not be changed
        final Path file = Paths.get("images/bitcoin.png");

        final byte[] key = "some-key".getBytes();

        try
        {
            final byte[] output = getMAC().generate(file, key);

            final String outputAsHex    = HexFormat.of().formatHex(output);
            final String expectedOutput = getMacForFile();

            assertEquals(expectedOutput, outputAsHex);
        }

        catch (IOException _)
        {
            fail(String.format("ERROR: couldn't open %s file", file));
        }
    }

    @Test
    void testMacCreationForNonExistentFile()
    {
        final Path nonExistentFile = Paths.get("dlhksdasdlkahdas");

        assertThrows(IOException.class, () ->
        {
            getMAC().generate(nonExistentFile, new byte[0]);
        });
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
    void testMacVerificationForFile() throws IOException
    {
        final byte[] validMac = HexFormat.of().parseHex(getMacForFile());

        final Path inputFile = Paths.get("images/bitcoin.png");
        final byte[] key     = "some-key".getBytes();

        assertTrue(getMAC().isValid(inputFile, key, validMac));
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
        final byte[] validMac = {0};

        final Path inputFile = Paths.get("images/bitcoin.png");
        final byte[] key     = "some-key".getBytes();

        assertFalse(getMAC().isValid(inputFile, key, validMac));
    }

    @Test
    void testVerifyMacWithNonExistingFile() throws IOException
    {
        final Path nonExistingFile = Paths.get("dlasdhjlkasjd/dkajhsdkjahsd");

        assertThrows(IOException.class, () ->
        {
            getMAC().isValid(nonExistingFile, new byte[0], new byte[0]);
        });
    }
}
