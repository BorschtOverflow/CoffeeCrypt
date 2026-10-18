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

public final class SHA3_512Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA3_512();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "38e05c33d7b067127f217d8c856e554fcff09c9320b8a5979ce2ff5d95dd27ba35d1fba50c562dfd1d6cc48bc9c5baa4390894418cc942d968f97bcb659419ed";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "24aae16f219637d3e6012319c66590a394eae25fd9b975f001ad97b5053856a8c0b485cc74235b2c0414a5ea3c5de40e1f9b96501a68f724a64a71ae2583be3e";
    }

    @Override
    protected String getFileHash()
    {
        return "c55b897426c8f6eff6431be7beb73a3b7a559f177f9f5c32a44e353c3c879f7c1c50e2e97235f210bd07766ebdcbed68f8fa620e90db592d714c003d4976ae8b";
    }
}
