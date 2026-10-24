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

public final class SHA2_224Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA2_224();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "e6755be27c2ddff46d3e431586eb40c398faba1ef44f01003df099ce";
    }

    @Override
    protected String getLargeTextFileHash()
    {
        return "dc03f958f04fe56480c09b3671a2b28be7d4f597b8eedc3e8f954f3c";
    }
}
