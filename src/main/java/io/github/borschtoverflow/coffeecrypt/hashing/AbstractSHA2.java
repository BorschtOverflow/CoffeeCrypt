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

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.util.Arrays;

/// Contain common logic for all SHA-2 hash functions
///
/// @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
abstract sealed class AbstractSHA2 implements HashFunction permits AbstractSHA2Int, AbstractSHA2Long
{
    @Override
    public abstract int getBlockSizeInBytes();

    /// Pads a message according to SHA-2 specification: <br>
    ///
    /// * ***`{original message}`***
    /// * ***`{1 (separator)}`***
    /// * ***`{zeroes}`***
    /// * ***`{original message length}`***
    ///
    /// The result should be a multiple of 512 bits
    ///
    /// @param message           A message to pad
    /// @param totalBitsInStream The total length of the original message/stream in bits
    ///
    /// @return A padded message in big endian order.
    protected byte[] padMessage(byte[] message, long totalBitsInStream)
    {
        final int blockSize    = getBlockSizeInBytes();
        final int lengthSize   = blockSize / 8;
        final int targetModulo = blockSize - lengthSize;

        final int zeroBytePaddingRequired = (targetModulo - (message.length + 1) % blockSize + blockSize) % blockSize;

        final int totalLength = message.length + 1 + zeroBytePaddingRequired + lengthSize;

        byte[] paddedMessage = Arrays.copyOf(message, totalLength);

        paddedMessage[message.length] = (byte) 0b10000000;

        final ByteBuffer buffer = ByteBuffer.wrap(paddedMessage).order(ByteOrder.BIG_ENDIAN);

        if (lengthSize == 8)
        {
            buffer.putLong(totalLength - 8, totalBitsInStream);
        }

        else
        {
            final int lengthPosition = totalLength - 16;

            buffer.putLong(lengthPosition, 0L); // High 64 bits
            buffer.putLong(lengthPosition + 8, totalBitsInStream); // Low 64 bits
        }

        return paddedMessage;
    }
}
