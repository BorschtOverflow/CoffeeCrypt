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

import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.Arrays;

/// @since v0.4.0
abstract sealed class AbstractSHA3 permits SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
{
    protected abstract boolean isSHAKE();

    /// AKA rate in bytes
    protected abstract int getBlockSizeInBytes();
    protected abstract int getOutputLengthInBytes();

    /// Round Constants
    // spotless:off
    private static final long[] RC =
    {
        0x0000000000000001L, 0x0000000000008082L,
        0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L,
        0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL,
        0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L,
        0x0000000080000001L, 0x8000000080008008L,
    };

    private static final int[][] ROTATION_OFFSETS =
    {
        {0 , 36, 3 , 41, 18},
        {1 , 44, 10, 45, 2 },
        {62, 6 , 43, 15, 61},
        {28, 55, 25, 21, 56},
        {27, 20, 39, 8 , 14},
    };
    // spotless:on

    /// Performs SHA-3 pad10*1
    ///
    /// @param message A message to pad
    /// @param isSHAKE Use padding for SHAKE
    ///
    /// @return A padded message
    protected byte[] padMessage(byte[] message, boolean isSHAKE)
    {
        final int blockSize = getBlockSizeInBytes();

        // Calculate remaining space in the current block
        int tailLength    = message.length % blockSize;
        int paddingLength = blockSize - tailLength;

        int totalLength = message.length + paddingLength;

        byte[] paddedMessage = Arrays.copyOf(message, totalLength);

        byte delimiter = (byte) (isSHAKE ? 0b00011111 : 0b00000110);

        paddedMessage[message.length] = delimiter;

        paddedMessage[totalLength - 1] |= (byte) 0b10000000;

        return paddedMessage;
    }

    protected void theta(long[] state, long[] C)
    {
        for (int x = 0; x < 5; x++)
        {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        for (int x = 0; x < 5; x++)
        {
            long d = C[(x + 4) % 5] ^ Long.rotateLeft(C[(x + 1) % 5], 1);

            for (int y = 0; y < 5; y++)
            {
                state[x + 5 * y] ^= d;
            }
        }
    }

    protected void rhoAndPi(long[] state, long[] B)
    {
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                int nx = y;
                int ny = (2 * x + 3 * y) % 5;

                long lane = state[x + 5 * y];

                int r = ROTATION_OFFSETS[x][y];

                B[nx + 5 * ny] = (r == 0) ? lane : Long.rotateLeft(lane, r);
            }
        }
    }

    protected void chi(long[] state, long[] B)
    {
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                int t = x + 5 * y;
                state[t] = B[t] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
            }
        }
    }

    protected void iota(long[] state, int round)
    {
        state[0] ^= RC[round];
    }

    protected void keccakPermute(long[] state)
    {
        long[] C = new long[5];
        long[] B = new long[25];

        for (int round = 0; round < 24; round++)
        {
            theta(state, C);
            rhoAndPi(state, B);
            chi(state, B);
            iota(state, round);
        }
    }

    protected void absorbMessageBlock(long[] state, byte[] block, int rateBytes)
    {
        final ByteBuffer byteBuffer = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);

        final int wordsToAbsorb = rateBytes / 8;

        for (int i = 0; i < wordsToAbsorb; i++)
        {
            state[i] ^= byteBuffer.getLong();
        }
    }

    protected void absorbArray(long[] state, byte[] data)
    {
        final int blockSize   = getBlockSizeInBytes();
        final boolean isShake = isSHAKE();

        final byte[] padded = padMessage(data, isShake);

        for (int offset = 0; offset < padded.length; offset += blockSize)
        {
            byte[] block = new byte[blockSize];
            System.arraycopy(padded, offset, block, 0, blockSize);
            absorbMessageBlock(state, block, blockSize);
            keccakPermute(state);
        }
    }

    protected void absorbFileStream(long[] state, Path file) throws IOException
    {
        final int blockSize   = getBlockSizeInBytes();
        final boolean isShake = isSHAKE();

        byte[] pendingBlock = new byte[blockSize];

        int pendingCount = 0;

        try (InputStream in = new BufferedInputStream(Files.newInputStream(file)))
        {
            int bytesRead;

            byte[] chunk = new byte[4096];

            while ((bytesRead = in.read(chunk)) != -1)
            {
                int offset = 0;

                while (offset < bytesRead)
                {
                    int toCopy = Math.min(bytesRead - offset, blockSize - pendingCount);
                    System.arraycopy(chunk, offset, pendingBlock, pendingCount, toCopy);
                    pendingCount += toCopy;
                    offset += toCopy;

                    if (pendingCount == blockSize)
                    {
                        absorbMessageBlock(state, pendingBlock, blockSize);
                        keccakPermute(state);
                        pendingCount = 0;
                    }
                }
            }
        }

        byte[] pendingData = Arrays.copyOf(pendingBlock, pendingCount);
        byte[] paddedTail  = padMessage(pendingData, isShake);

        for (int offset = 0; offset < paddedTail.length; offset += blockSize)
        {
            byte[] block = new byte[blockSize];
            System.arraycopy(paddedTail, offset, block, 0, blockSize);
            absorbMessageBlock(state, block, blockSize);
            keccakPermute(state);
        }
    }

    /// Squeezes output bytes from the Keccak state
    protected byte[] squeeze(long[] state, long hashLengthInBytes)
    {
        final int blockSize = getBlockSizeInBytes();

        ByteBuffer outputBuffer = ByteBuffer.allocate((int) hashLengthInBytes).order(ByteOrder.LITTLE_ENDIAN);

        byte[] stateBytes = new byte[200];

        long generatedBytes = 0;

        while (generatedBytes < hashLengthInBytes)
        {
            ByteBuffer temp = ByteBuffer.wrap(stateBytes).order(ByteOrder.LITTLE_ENDIAN);

            for (int i = 0; i < 25; i++)
            {
                temp.putLong(state[i]);
            }

            int chunk = (int) Math.min(blockSize, hashLengthInBytes - generatedBytes);

            outputBuffer.put(stateBytes, 0, chunk);
            generatedBytes += chunk;

            if (generatedBytes < hashLengthInBytes)
            {
                keccakPermute(state);
            }
        }

        return outputBuffer.array();
    }

    protected byte[] squeeze(long[] state)
    {
        return squeeze(state, getOutputLengthInBytes());
    }

    // ----------------------------- Fixed length -----------------------------
    protected byte[] hashData(byte[] input)
    {
        long[] state = new long[25];
        absorbArray(state, input);
        return squeeze(state);
    }

    protected byte[] hashFile(Path file) throws IOException
    {
        long[] state = new long[25];
        absorbFileStream(state, file);
        return squeeze(state);
    }

    // ----------------------------- Variable length -----------------------------
    protected byte[] hashData(byte[] input, long hashLengthInBytes)
    {
        long[] state = new long[25];
        absorbArray(state, input);
        return squeeze(state, hashLengthInBytes);
    }

    protected byte[] hashFile(Path file, long hashLengthInBytes) throws IOException
    {
        long[] state = new long[25];
        absorbFileStream(state, file);
        return squeeze(state, hashLengthInBytes);
    }
}
