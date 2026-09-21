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

public final class SHA2_512t256Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA2_512t256();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "0686f0a605973dc1bf035d1e2b9bad1985a0bff712ddd88abd8d2593e5f99030";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "cbfc11533b66f948ae8645fdeec7dff079aa14168355dbb603bd6b2a770a9dcc";
    }

    @Override
    protected String getFileHash()
    {
        return "297d0d9d47eb8af62af573dfc8384bd793352a444fd864c975d133963f39700c";
    }
}
