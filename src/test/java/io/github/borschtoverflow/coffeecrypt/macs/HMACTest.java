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

package io.github.borschtoverflow.coffeecrypt.macs;

import io.github.borschtoverflow.coffeecrypt.hashing.SHA2_256;

public final class HMACTest extends AbstractMACTest
{
    @Override
    MAC getMAC()
    {
        return new HMAC(new SHA2_256());
    }

    @Override
    String getHelloWorldMac()
    {
        return "241c625395c4efe52f91ae80db0d24d24fe530dfdd3cc99e4591d2c3c85a0909";
    }

    @Override
    String getLargeInputMac()
    {
        return "49ba261778e4fc18337ce9f136205eba413a52d9c31d597c6092daff00b111fc";
    }

    @Override
    String getMacForFile()
    {
        return "ef67265db289cfda2d5286f8a2a644526bab3d5202f7730dae7e5dc87ac94141";
    }
}
