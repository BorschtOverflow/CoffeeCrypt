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

public final class SHA2_512Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA2_512();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "a48c15e6e696f99d7d3163245e00eabbdd6e005a8e81c3ef7ca8d60cdf5a93f5d3f3772c6a3c19f7110cb129830cd96876bd71b7c8cb45cb6b6b781125ba6d75";
    }

    @Override
    protected String getLargeTextFileHash()
    {
        return "d13534276512f97ceab7d28f9567bbc0440af7a92339f604c06c0534e6c5e4c37ecc4540a266e60bbecc38c0551adb66ad491d8156150a7e851ba25c3f530eb3";
    }
}
