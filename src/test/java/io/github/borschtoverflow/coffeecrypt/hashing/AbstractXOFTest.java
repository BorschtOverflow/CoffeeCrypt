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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.borschtoverflow.coffeecrypt.AbstractTest;

abstract class AbstractXOFTest extends AbstractTest
{
    protected abstract XOF getExtendableHashFunction();
    protected abstract long getOutputSizeInBytes();
    protected abstract String getExtendableHelloWorldHash(); // "Hello, World!"
    protected abstract String getExtendableLargeStringHash(); // output from getLargeString()
    protected abstract String getExtendableLargeTextFileHash(); // output from generateLargeTextFile()

    @Test
    void testNullInput()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class,
                () -> getExtendableHashFunction().hashData(null, getOutputSizeInBytes()));

        final String exceptionMessage = exception.getMessage();

        assertEquals("input is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testNullFile()
    {
        final Exception exception = assertThrows(IllegalArgumentException.class,
                () -> getExtendableHashFunction().hashFile(null, getOutputSizeInBytes()));

        final String exceptionMessage = exception.getMessage();

        assertEquals("file is marked non-null but is null", exceptionMessage);
    }

    @Test
    void testEmptyInput()
    {
        final byte[] emptyInput = new byte[0];

        assertDoesNotThrow(() ->
        {
            byte[] digest = getExtendableHashFunction().hashData(emptyInput, getOutputSizeInBytes());
            assertNotNull(digest);
        });
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1, -10, -999999})
    void testZeroOrLessLengthInputForFile(long hashLengthInBytes)
    {
        final Path fakePath = Paths.get("some/fake/path");

        final Exception exception = assertThrows(IllegalArgumentException.class,
                () -> getExtendableHashFunction().hashFile(fakePath, hashLengthInBytes));

        final String exceptionMessage = exception.getMessage();

        assertEquals("ERROR: hashLengthInBytes cannot be 0 or less!", exceptionMessage);
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1, -10, -999999})
    void testZeroOrLessLengthInputForData(long hashLengthInBytes)
    {
        final Exception exception = assertThrows(IllegalArgumentException.class,
                () -> getExtendableHashFunction().hashData(new byte[]{1, 2, 3}, hashLengthInBytes));

        final String exceptionMessage = exception.getMessage();

        assertEquals("ERROR: hashLengthInBytes cannot be 0 or less!", exceptionMessage);
    }

    @Test
    void testHelloWorld()
    {
        final byte[] input  = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        final byte[] output = getExtendableHashFunction().hashData(input, getOutputSizeInBytes());

        final String expectedResult    = getExtendableHelloWorldHash();
        final String outputAsHexString = HexFormat.of().formatHex(output);

        assertEquals(expectedResult, outputAsHexString);
    }

    /// Must produce the same result given the same input
    @Test
    void testDeterminism()
    {
        final byte[] input = "Hello, World!".getBytes(StandardCharsets.UTF_8);

        final byte[] output1 = getExtendableHashFunction().hashData(input, getOutputSizeInBytes());
        final byte[] output2 = getExtendableHashFunction().hashData(input, getOutputSizeInBytes());
        final byte[] output3 = getExtendableHashFunction().hashData(input, getOutputSizeInBytes());

        assertArrayEquals(output1, output2);
        assertArrayEquals(output2, output3);
    }

    @Test
    void testDifferentInstances()
    {
        final byte[] input = "some input".getBytes(StandardCharsets.UTF_8);

        final XOF hash1 = getExtendableHashFunction();
        final XOF hash2 = getExtendableHashFunction();

        final byte[] output0 = getExtendableHashFunction().hashData(input, getOutputSizeInBytes());
        final byte[] output1 = hash1.hashData(input, getOutputSizeInBytes());
        final byte[] output2 = hash2.hashData(input, getOutputSizeInBytes());

        assertArrayEquals(output0, output1);
        assertArrayEquals(output1, output2);
        assertArrayEquals(output2, output0);
    }

    @Test
    void testSlightlyDifferentInput()
    {
        final byte[] input1 = {0};
        final byte[] input2 = {1};

        final byte[] hash1 = getExtendableHashFunction().hashData(input1, getOutputSizeInBytes());
        final byte[] hash2 = getExtendableHashFunction().hashData(input2, getOutputSizeInBytes());

        assertFalse(Arrays.equals(hash1, hash2));
    }

    @Test
    void testLargeTextInput()
    {
        final String largeInput = getLargeString();

        final byte[] inputAsBytes = largeInput.getBytes();

        final byte[] output = getExtendableHashFunction().hashData(inputAsBytes, getOutputSizeInBytes());

        final String expectedResult    = getExtendableLargeStringHash();
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
        final byte[] expectedHash = getExtendableHashFunction().hashData(inputBytes, getOutputSizeInBytes());

        try (ExecutorService executor = Executors.newFixedThreadPool(threadCount))
        {
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
                        lastResult = getExtendableHashFunction().hashData(inputBytes, getOutputSizeInBytes());
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
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testConcurrentMultipleInputs() throws InterruptedException
    {
        final XOF sharedHash = getExtendableHashFunction();

        final int threadCount = 20;
        final int iterations  = 500;

        ConcurrentLinkedQueue<Throwable> errors;

        try (ExecutorService executor = Executors.newFixedThreadPool(threadCount))
        {
            CountDownLatch startLatch = new CountDownLatch(1);
            errors = new ConcurrentLinkedQueue<>();

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
                        byte[] standaloneExpected = getExtendableHashFunction().hashData(inputBytes,
                                getOutputSizeInBytes());

                        for (int k = 0; k < iterations; k++)
                        {
                            byte[] result = sharedHash.hashData(inputBytes, getOutputSizeInBytes());

                            if (!Arrays.equals(standaloneExpected, result))
                            {
                                throw new AssertionError(String
                                        .format("Race condition detected on Thread %d at iteration %d", threadID, k));
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
        }

        if (!errors.isEmpty())
        {
            fail("Thread-safety failures detected (" + errors.size() + " errors):\n" + errors.peek().getMessage());
        }
    }

    @Test
    void testLargeTextFileHashing() throws IOException
    {
        final Path largeTextFile = getLargeTextFilePath();

        try
        {
            final byte[] output = getExtendableHashFunction().hashFile(largeTextFile, getOutputSizeInBytes());

            final String outputAsHex    = HexFormat.of().formatHex(output);
            final String expectedOutput = getExtendableLargeTextFileHash();

            assertEquals(expectedOutput, outputAsHex);
        }

        catch (IOException _)
        {
            fail(String.format("ERROR: couldn't open %s file", largeTextFile));
        }
    }

    @Test
    void testHashNonExistentFile()
    {
        final Path nonExistentFile = Paths.get("dlhksdasdlkahdas");

        assertThrows(IOException.class,
                () -> getExtendableHashFunction().hashFile(nonExistentFile, getOutputSizeInBytes()));
    }
}
