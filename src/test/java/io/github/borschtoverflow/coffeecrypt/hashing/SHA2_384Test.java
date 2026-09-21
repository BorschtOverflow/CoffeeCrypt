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

public final class SHA2_384Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA2_384();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "4b584c4d21c71379d8ea24c2f3856809bf4cc21021979bf5addb8ac583c567fa410ac6a8bdc777dbc4271c535e06cf77";
    }

    @Override
    protected String getFileHash()
    {
        return "10c35129f338a0f11a31c48b81aa81ae742729dab681d54955feaff38564c47d56079cff3d36e4bb2fbfa09c473484d2";
    }
}
