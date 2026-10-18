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

public final class SHA3_224Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA3_224();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "853048fb8b11462b6100385633c0cc8dcdc6e2b8e376c28102bc84f2";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "8f7cd30a0fc59ab9dbafc208ad82e6ab996baa82d700017a25aeb48e";
    }

    @Override
    protected String getFileHash()
    {
        return "0aac309443c35ea53aea389db382645ae58addd01a680e7d488f70b3";
    }
}
