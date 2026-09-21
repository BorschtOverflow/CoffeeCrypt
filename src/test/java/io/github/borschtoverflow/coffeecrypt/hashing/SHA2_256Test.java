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

public final class SHA2_256Test extends AbstractHashFunctionTest
{
    @Override
    protected HashFunction getHashFunction()
    {
        return new SHA2_256();
    }

    @Override
    protected String getHelloWorldHash()
    {
        return "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
    }

    @Override
    protected String getLargeStringHash()
    {
        return "b4f707f1d87d72ed275ec4dba7f4f6be53c6c07a3fb764fcdf12e5e3a185320d";
    }

    @Override
    protected String getFileHash()
    {
        return "cc9304c27300ad77600230406ea0890904de2a2269d2966449175208f5621d71";
    }
}
