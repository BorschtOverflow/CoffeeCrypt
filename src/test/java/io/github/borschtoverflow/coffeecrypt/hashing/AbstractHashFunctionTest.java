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

package io.github.borschtoverflow.coffeecrypt.hashing;

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
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

abstract class AbstractHashFunctionTest
{
    protected abstract HashFunction getHashFunction();

    protected abstract String getHelloWorldHash(); // "Hello, World!"
    protected abstract String getLargeStringHash(); // output from getLargeString()
    protected abstract String getFileHash(); // images/bitcoin.png

    String getLargeString()
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
            getHashFunction().hashData(null);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("input is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testNullFile()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class, () ->
        {
            getHashFunction().hashFile(null);
        });

        final String exceptionMessage = exception.getMessage();

        assertEquals("file is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testEmptyInput()
    {
        final byte[] emptyInput = new byte[0];

        assertDoesNotThrow(() ->
        {
            byte[] digest = getHashFunction().hashData(emptyInput);
            assertNotNull(digest);
        });
    }

    @Test
    void testHelloWorld()
    {
        final byte[] input  = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        final byte[] output = getHashFunction().hashData(input);

        final String expectedResult    = getHelloWorldHash();
        final String outputAsHexString = HexFormat.of().formatHex(output);

        assertEquals(expectedResult, outputAsHexString);
    }

    /// Must produce the same result given the same input
    @Test
    void testDeterminism()
    {
        final byte[] input = "Hello, World!".getBytes(StandardCharsets.UTF_8);

        final byte[] output1 = getHashFunction().hashData(input);
        final byte[] output2 = getHashFunction().hashData(input);
        final byte[] output3 = getHashFunction().hashData(input);

        assertArrayEquals(output1, output2);
        assertArrayEquals(output2, output3);
    }

    @Test
    void testDifferentInstances()
    {
        final byte[] input = "some input".getBytes(StandardCharsets.UTF_8);

        final byte[] ouput0 = getHashFunction().hashData(input);

        final HashFunction hash1 = getHashFunction();
        final HashFunction hash2 = getHashFunction();

        final byte[] ouput1 = hash1.hashData(input);
        final byte[] ouput2 = hash2.hashData(input);

        assertArrayEquals(ouput0, ouput1);
        assertArrayEquals(ouput1, ouput2);
        assertArrayEquals(ouput2, ouput0);
    }

    @Test
    void testSlightlyDifferentInput()
    {
        final byte[] input1 = {0};
        final byte[] input2 = {1};

        final byte[] hash1 = getHashFunction().hashData(input1);
        final byte[] hash2 = getHashFunction().hashData(input2);

        assertFalse(Arrays.equals(hash1, hash2));
    }

    @Test
    void testLargeTextInput()
    {
        final String largeInput = getLargeString();

        final byte[] inputAsBytes = largeInput.getBytes();

        final byte[] output = getHashFunction().hashData(inputAsBytes);

        final String expectedResult    = getLargeStringHash();
        final String outputAsHexString = HexFormat.of().formatHex(output);

        assertEquals(expectedResult, outputAsHexString);
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testConcurrentExecutionSameInstance() throws InterruptedException, ExecutionException
    {
        final int tasksPerThread = 100;
        final int threadCount    = 16;
        final String inputString = "Concurrent safety check input string 1234567890";
        final byte[] inputBytes  = inputString.getBytes(StandardCharsets.UTF_8);

        // Compute baseline hash in single-threaded context
        final byte[] expectedHash = getHashFunction().hashData(inputBytes);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch readyLatch = new CountDownLatch(threadCount); // Synchronizes thread startup
        CountDownLatch startLatch = new CountDownLatch(1); // Starts all threads at the exact same moment

        List<Future<byte[]>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++)
        {
            futures.add(executor.submit(() ->
            {
                readyLatch.countDown();
                startLatch.await(); // Hold until all worker threads are ready

                byte[] lastResult = null;

                for (int j = 0; j < tasksPerThread; j++)
                {
                    lastResult = getHashFunction().hashData(inputBytes);
                }

                return lastResult;
            }));
        }

        // Wait for all threads to align at the starting gate
        readyLatch.await();
        // Release all threads simultaneously to maximize contention
        startLatch.countDown();

        // Validate results across all threads
        for (Future<byte[]> future : futures)
        {
            byte[] threadResult = future.get();

            assertArrayEquals(expectedHash, threadResult,
                    "Thread produced an incorrect hash under concurrent load. Instance is NOT thread-safe.");
        }

        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testConcurrentMultipleInputs() throws InterruptedException
    {
        final HashFunction sharedHash = getHashFunction();

        final int threadCount = 20;
        final int iterations  = 500;

        ExecutorService                  executor   = Executors.newFixedThreadPool(threadCount);
        CountDownLatch                   startLatch = new CountDownLatch(1);
        ConcurrentLinkedQueue<Throwable> errors     = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threadCount; i++)
        {
            final int threadID = i;
            executor.submit(() ->
            {
                try
                {
                    startLatch.await();

                    String input      = "Input text from thread-" + threadID;
                    byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

                    // Compute clean standalone hash for validation target
                    byte[] standaloneExpected = getHashFunction().hashData(inputBytes);

                    for (int k = 0; k < iterations; k++)
                    {
                        byte[] result = sharedHash.hashData(inputBytes);

                        if (!Arrays.equals(standaloneExpected, result))
                        {
                            throw new AssertionError(
                                    String.format("Race condition detected on Thread %d at iteration %d", threadID, k));
                        }
                    }
                }

                catch (Throwable throwable)
                {
                    errors.add(throwable);
                }
            });
        }

        startLatch.countDown(); // Start race
        executor.shutdown();

        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

        if (!errors.isEmpty())
        {
            fail("Thread-safety failures detected (" + errors.size() + " errors):\n" + errors.peek().getMessage());
        }
    }

    @Test
    void testFileHashing()
    {
        // Just needed a file that would not be changed
        final Path file = Paths.get("images/bitcoin.png");

        try
        {
            final byte[] output = getHashFunction().hashFile(file);

            final String outputAsHex    = HexFormat.of().formatHex(output);
            final String expectedOutput = getFileHash();

            assertEquals(expectedOutput, outputAsHex);
        }

        catch (IOException _)
        {
            fail(String.format("ERROR: couldn't open %s file", file));
        }
    }

    @Test
    void testHashNonExistentFile()
    {
        final Path nonExistentFile = Paths.get("dlhksdasdlkahdas");

        assertThrows(IOException.class, () ->
        {
            getHashFunction().hashFile(nonExistentFile);
        });
    }
}
