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

public final class SHAKE128Test extends AbstractXOFTest
{
    @Override
    protected XOF getExtendableHashFunction()
    {
        return new SHAKE128();
    }

    @Override
    protected long getOutputSizeInBytes()
    {
        return 64;
    }

    @Override
    protected String getExtendableHelloWorldHash()
    {
        return "2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cbdd588f2c5dd4e465dfbafaa7c5634249c8929dc04165a9edb26be19ce036196d1";
    }

    @Override
    protected String getExtendableLargeStringHash()
    {
        return "be161c38ec535a68d007bae24c9cf61d9d6743f4bfb5cddce8c3af09505b01e7c09b61c02a90655d5faeee92a149ded7dc2b07f43025d9d7196a773ceb80f4d1";
    }

    @Override
    protected String getExtendableLargeTextFileHash()
    {
        return "bbd43e65c5fa2546d71650f14e1ca87fcb435bac654293be3d41dfb694a64b33d219577555125c7d9df7311ce93464dd37816ef1ce3e6b257a82b50ddf55e71f";
    }
}
