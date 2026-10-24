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
    protected String getLargeTextFileHash()
    {
        return "cfb1fe941ffeadb16508456a64f68beae1e828eb5c6297d73ceb771a4273e625df80c7a911e63819fbad4d74eb693778";
    }
}
