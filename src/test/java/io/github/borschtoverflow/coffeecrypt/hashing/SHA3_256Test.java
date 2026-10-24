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

public final class SHA3_256Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA3_256();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "6ca5af7442f8938346d39a99cfc5b87fe630dc681f668b3ecc0d14c08db969c9";
    }

    @Override
    protected String getLargeTextFileHash()
    {
        return "fd482de2b423d0ffad2d34004e0620b4567aa4fb5b636c4d1ce362a607832e9b";
    }
}
