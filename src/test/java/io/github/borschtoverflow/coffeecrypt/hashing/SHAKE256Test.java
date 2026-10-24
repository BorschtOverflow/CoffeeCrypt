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

public final class SHAKE256Test extends AbstractXOFTest
{
    @Override
    protected XOF getExtendableHashFunction()
    {
        return new SHAKE256();
    }

    @Override
    protected long getOutputSizeInBytes()
    {
        return 74;
    }

    @Override
    protected String getExtendableHelloWorldHash()
    {
        return "b3be97bfd978833a65588ceae8a34cf59e95585af62063e6b89d0789f372424e8b0d1be4f21b40ce5a83a438473271e0661854f02d431db74e6904d6c347d757a33b44f18e740bd11978";
    }

    @Override
    protected String getExtendableLargeStringHash()
    {
        return "78ff22f5493a15f885d7bfcd9cde32bee2a2d25f9b311f357e8e22b62996e2f2c0ad92888ad1169abd53b50da1da2627120b728b17d862b0625cd21fcce004cad32d10e970e3236dc60b";
    }

    @Override
    protected String getExtendableLargeTextFileHash()
    {
        return "aa7652f342d83f4b01b31a64d542c35cc23a0a1cea8fd6ca10cdba98c97704a74e933c9a7971ed224e96e23defe8f4ee4726522443b7a76ff411bf75dcee603d1ae72c3d4f6dcc0867ad";
    }
}
