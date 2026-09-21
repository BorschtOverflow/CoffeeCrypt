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

sealed abstract class AbstractSHA2Long extends AbstractSHA2 permits SHA2_384, SHA2_512, SHA2_512t224, SHA2_512t256
{
    /// Constants for [SHA2_384], [SHA2_512], [SHA2_512t224] and [SHA2_512t256]
    ///
    /// These words represent the first sixty-four bits of the
    /// fractional parts of the cube roots of the first eighty prime numbers.
    ///
    /// In hex, these constant words are (from left to right)
    // spotless:off
    private static final long[] K =
    {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
        0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
        0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
        0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
        0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
        0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
        0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
        0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
        0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
        0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
        0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
        0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
        0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
        0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L,
    };
    // spotless:on

    /// The shift right operation
    ///
    /// @param x 64 bit word
    /// @param n Number of bits to be shifted
    ///
    /// @return The result of shifting **`x`** by **`n`**
    private long SHR(long x, int n)
    {
        return x >>> n;
    }

    /// The rotate right (circular right shift) operation
    ///
    /// @param x 64 bit word
    /// @param n Number of bits to be rotated
    ///
    /// @return The result of a circular right shift of **`x`** by **`n`**
    private long ROTR(long x, int n)
    {
        return Long.rotateRight(x, n);
    }

    /// The Choice function
    private long Ch(long x, long y, long z)
    {
        return (x & y) ^ (~x & z);
    }

    /// The Majority function
    private long Maj(long x, long y, long z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private long uppercaseSigma0(long x)
    {
        return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
    }

    private long uppercaseSigma1(long x)
    {
        return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
    }

    private long lowercaseSigma0(long x)
    {
        return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
    }

    private long lowercaseSigma1(long x)
    {
        return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
    }

    /// Processes a single 1024-bit block and updates the state (in-place)
    ///
    /// @param block A 1024-bit (128-byte) block
    /// @param H     An internal 64-bit state array
    protected void processBlock(byte[] block, long[] H)
    {
        // Message schedule
        long[] W = new long[80];

        ByteBuffer byteBuffer = ByteBuffer.wrap(block).order(ByteOrder.BIG_ENDIAN);

        for (int t = 0; t <= 15; t++)
        {
            W[t] = byteBuffer.getLong();
        }

        for (int t = 16; t <= 79; t++)
        {
            W[t] = W[t - 16] + lowercaseSigma0(W[t - 15]) + W[t - 7] + lowercaseSigma1(W[t - 2]);
        }

        // Eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)st
        // hashvalue:
        long a = H[0];
        long b = H[1];
        long c = H[2];
        long d = H[3];
        long e = H[4];
        long f = H[5];
        long g = H[6];
        long h = H[7];

        for (int t = 0; t <= 79; t++)
        {
            long T1 = h + uppercaseSigma1(e) + Ch(e, f, g) + K[t] + W[t];
            long T2 = uppercaseSigma0(a) + Maj(a, b, c);

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

    protected static final int BLOCK_SIZE = 128;

    /// @return Initial Hash Values
    protected abstract long[] getIV();
    protected abstract int getHashLengthInBytes();

    @Override
    public byte[] hashData(byte[] input)
    {
        final long totalBitsInStream = (long) input.length * 8;

        long[] H = getIV().clone();

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

        long[] H = getIV().clone();

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

        // SHA-384 / SHA-512 128-byte block tail calculation

        int padLength;

        if (pendingCount < 112)
        {
            padLength = 128 - pendingCount;
        }

        else
        {
            padLength = 256 - pendingCount;
        }

        byte[] tailWithPadding = new byte[pendingCount + padLength];

        System.arraycopy(pendingBlock, 0, tailWithPadding, 0, pendingCount);

        // Append Separator
        tailWithPadding[pendingCount] = (byte) 0b10000000;

        // Write 128-bit length into reserved last 16 bytes
        final int lengthPosition = tailWithPadding.length - 16;

        ByteBuffer.wrap(tailWithPadding).order(ByteOrder.BIG_ENDIAN).putLong(lengthPosition, 0L) // High 64 bits
                .putLong(lengthPosition + 8, totalBitsInStream); // Low 64 bits

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
        return 128;
    }

    private byte[] formatOutput(long[] H)
    {
        final int outputBytes = getHashLengthInBytes();
        final int wordsToOutput = (int) Math.ceil(outputBytes / 8.0); // Output 64-bit words

        ByteBuffer outputBuffer = ByteBuffer.allocate(wordsToOutput * 8).order(ByteOrder.BIG_ENDIAN);

        for (int i = 0; i < wordsToOutput; i++)
        {
            outputBuffer.putLong(H[i]);
        }

        byte[] fullResult = outputBuffer.array();

        if (fullResult.length == outputBytes)
        {
            return fullResult;
        }

        // For truncated outputs like SHA-512/224 (28 bytes), return exact byte length
        byte[] truncatedResult = new byte[outputBytes];
        System.arraycopy(fullResult, 0, truncatedResult, 0, outputBytes);

        return truncatedResult;
    }
}
