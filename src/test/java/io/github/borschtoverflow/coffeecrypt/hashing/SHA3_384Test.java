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

public final class SHA3_384Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA3_384();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "aa9ad8a49f31d2ddcabbb7010a1566417cff803fef50eba239558826f872e468c5743e7f026b0a8e5b2d7a1cc465cdbe";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "29f866a58b6cdcf66ec39c72cd29735ec64f818f8317e80b63b89c107dc930e26f62af66e8cf8b26fb94aba127d06c34";
    }

    @Override
    protected String getFileHash()
    {
        return "507c0d999bda382a88401ee1a364f2a8da4e849b2ca967bde3a771300bfd395fbb8a6d8c5bf1b4b839326e1299958ca6";
    }
}
