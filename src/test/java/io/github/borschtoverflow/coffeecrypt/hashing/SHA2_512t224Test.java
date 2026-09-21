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

public final class SHA2_512t224Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA2_512t224();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "766745f058e8a0438f19de48ae56ea5f123fe738af39bca050a7547a";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "2a750533e043bbd962b13b6085169574a5101c004172b2a448855a0d";
    }

    @Override
    protected String getFileHash()
    {
        return "0aa55c45f718c8661ead2ab3d5b04a7cdeb05e0bea9da9093ae1387f";
    }
}
