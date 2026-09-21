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

sealed abstract class AbstractSHA2Int extends AbstractSHA2 permits SHA2_224, SHA2_256
{
    /// Constants for [SHA2_224] and [SHA2_256]
    ///
    /// These words represent the first thirty-two bits of the
    /// fractional parts of the cube roots of the first sixty-four prime numbers.
    ///
    /// In hex, these constant words are (from left to right)
    // spotless:off
    private static final int[] K =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    // spotless:on

    /// The shift right operation
    ///
    /// @param x 32 bit word
    /// @param n Number of bits to be shifted
    ///
    /// @return The result of shifting **`x`** by **`n`**
    private int SHR(int x, int n)
    {
        return x >>> n;
    }

    /// The rotate right (circular right shift) operation
    ///
    /// @param x 32 bit word
    /// @param n Number of bits to be rotated
    ///
    /// @return The result of a circular right shift of **`x`** by **`n`**
    private int ROTR(int x, int n)
    {
        return Integer.rotateRight(x, n);
    }

    /// The Choice function
    private int Ch(int x, int y, int z)
    {
        return (x & y) ^ (~x & z);
    }

    /// The Majority function
    private int Maj(int x, int y, int z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private int uppercaseSigma0(int x)
    {
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    }

    private int uppercaseSigma1(int x)
    {
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }

    private int lowercaseSigma0(int x)
    {
        return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
    }

    private int lowercaseSigma1(int x)
    {
        return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
    }

    /// Processes a single 512-bit block and updates the state (in-place)
    ///
    /// @param block A 512-bit block
    /// @param H     An internal state
    protected void processBlock(byte[] block, int[] H)
    {
        // Message schedule
        int[] W = new int[64];

        ByteBuffer byteBuffer = ByteBuffer.wrap(block).order(ByteOrder.BIG_ENDIAN);

        for (int t = 0; t <= 15; t++)
        {
            W[t] = byteBuffer.getInt();
        }

        for (int t = 16; t <= 63; t++)
        {
            W[t] = W[t - 16] + lowercaseSigma0(W[t - 15]) + W[t - 7] + lowercaseSigma1(W[t - 2]);
        }

        // Eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)st
        // hashvalue:
        int a = H[0];
        int b = H[1];
        int c = H[2];
        int d = H[3];
        int e = H[4];
        int f = H[5];
        int g = H[6];
        int h = H[7];

        for (int t = 0; t <= 63; t++)
        {
            int T1 = h + uppercaseSigma1(e) + Ch(e, f, g) + K[t] + W[t];
            int T2 = uppercaseSigma0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Compute the ith intermediate hash value H(i):
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    protected static final int BLOCK_SIZE = 64;

    /// @return Initial Hash Values
    protected abstract int[] getIV();
    protected abstract int getHashLengthInBytes();

    @Override
    public byte[] hashData(byte[] input)
    {
        final long totalBitsInStream = (long) input.length * 8;

        int[] H = getIV().clone();

        byte[] paddedMessage = padMessage(input, totalBitsInStream);
        byte[] block         = new byte[BLOCK_SIZE];

        for (int offset = 0; offset < paddedMessage.length; offset += BLOCK_SIZE)
        {
            System.arraycopy(paddedMessage, offset, block, 0, BLOCK_SIZE);
            processBlock(block, H);
        }

        return formatOutput(H);
    }

    @Override
    public byte[] hashFile(Path file) throws IOException
    {
        final int CHUNK_SIZE = 4096;

        int[] H = getIV().clone();

        byte[] chunk          = new byte[CHUNK_SIZE];
        byte[] pendingBlock   = new byte[BLOCK_SIZE];
        long   totalBytesRead = 0;
        int    pendingCount   = 0;

        try (InputStream in = new BufferedInputStream(Files.newInputStream(file)))
        {
            int bytesRead;

            while ((bytesRead = in.read(chunk)) != -1)
            {
                int offset = 0;

                totalBytesRead += bytesRead;

                while (offset < bytesRead)
                {
                    final int toCopy = Math.min(bytesRead - offset, BLOCK_SIZE - pendingCount);

                    System.arraycopy(chunk, offset, pendingBlock, pendingCount, toCopy);

                    pendingCount += toCopy;
                    offset += toCopy;

                    if (pendingCount == BLOCK_SIZE)
                    {
                        processBlock(pendingBlock, H);
                        pendingCount = 0;
                    }
                }
            }
        }

        final long totalBitsInStream = totalBytesRead * 8;

        // Construct tail padding directly on the stream
        // 1 byte for 0b10000000 separator + 8 bytes for length field = 9 bytes minimum
        // metadata

        int padLength;

        if (pendingCount < 56)
        {
            padLength = 64 - pendingCount;
        }

        else
        {
            padLength = 128 - pendingCount;
        }

        byte[] tailWithPadding = new byte[pendingCount + padLength];

        // Copy remaining unpadded bytes
        System.arraycopy(pendingBlock, 0, tailWithPadding, 0, pendingCount);

        // Append separator
        tailWithPadding[pendingCount] = (byte) 0b10000000;

        // Append total bit length in BIG_ENDIAN at the last 8 bytes of tailWithPadding
        ByteBuffer.wrap(tailWithPadding).order(ByteOrder.BIG_ENDIAN).putLong(tailWithPadding.length - 8,
                totalBitsInStream);

        // Process final 1 or 2 padded tail blocks
        byte[] block = new byte[BLOCK_SIZE];

        for (int offset = 0; offset < tailWithPadding.length; offset += BLOCK_SIZE)
        {
            System.arraycopy(tailWithPadding, offset, block, 0, BLOCK_SIZE);
            processBlock(block, H);
        }

        return formatOutput(H);
    }

    @Override
    public int getBlockSizeInBytes()
    {
        return 64;
    }

    private byte[] formatOutput(int[] H)
    {
        final int outputBytes = getHashLengthInBytes();
        final int wordsToOutput = outputBytes / 4; // 7 words for SHA-224, 8 words for SHA-256

        final ByteBuffer outputBuffer = ByteBuffer.allocate(outputBytes).order(ByteOrder.BIG_ENDIAN);

        for (int i = 0; i < wordsToOutput; i++)
        {
            outputBuffer.putInt(H[i]);
        }

        return outputBuffer.array();
    }
}
