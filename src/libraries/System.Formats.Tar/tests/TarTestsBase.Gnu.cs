﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using Xunit;

namespace System.Formats.Tar.Tests
{
    public abstract partial class TarTestsBase : FileCleanupTestBase
    {
        protected void SetRegularFile(GnuTarEntry regularFile)
        {
            SetCommonRegularFile(regularFile);
            SetPosixProperties(regularFile);
            SetGnuProperties(regularFile);
        }

        protected void SetDirectory(GnuTarEntry directory)
        {
            SetCommonDirectory(directory);
            SetPosixProperties(directory);
            SetGnuProperties(directory);
        }

        protected void SetHardLink(GnuTarEntry hardLink)
        {
            SetCommonHardLink(hardLink);
            SetPosixProperties(hardLink);
            SetGnuProperties(hardLink);
        }

        protected void SetSymbolicLink(GnuTarEntry symbolicLink)
        {
            SetCommonSymbolicLink(symbolicLink);
            SetPosixProperties(symbolicLink);
            SetGnuProperties(symbolicLink);
        }

        protected void SetCharacterDevice(GnuTarEntry characterDevice)
        {
            SetCharacterDeviceProperties(characterDevice);
            SetGnuProperties(characterDevice);
        }

        protected void SetBlockDevice(GnuTarEntry blockDevice)
        {
            SetBlockDeviceProperties(blockDevice);
            SetGnuProperties(blockDevice);
        }

        protected void SetFifo(GnuTarEntry fifo)
        {
            SetFifoProperties(fifo);
            SetGnuProperties(fifo);
        }

        protected void SetGnuProperties(GnuTarEntry entry)
        {
            Assert.Equal(default, entry.AccessTime);
            entry.AccessTime = TestAccessTime;

            Assert.Equal(default, entry.ChangeTime);
            entry.ChangeTime = TestChangeTime;
        }

        protected void VerifyRegularFile(GnuTarEntry regularFile, bool isWritable)
        {
            VerifyPosixRegularFile(regularFile, isWritable);
            VerifyGnuProperties(regularFile);
        }

        protected void VerifyDirectory(GnuTarEntry directory)
        {
            VerifyPosixDirectory(directory);
            VerifyGnuProperties(directory);
        }

        protected void VerifyHardLink(GnuTarEntry hardLink)
        {
            VerifyPosixHardLink(hardLink);
            VerifyGnuProperties(hardLink);
        }

        protected void VerifySymbolicLink(GnuTarEntry symbolicLink)
        {
            VerifyPosixSymbolicLink(symbolicLink);
            VerifyGnuProperties(symbolicLink);
        }

        protected void VerifyCharacterDevice(GnuTarEntry characterDevice)
        {
            VerifyPosixCharacterDevice(characterDevice);
            VerifyGnuProperties(characterDevice);
        }

        protected void VerifyBlockDevice(GnuTarEntry blockDevice)
        {
            VerifyPosixBlockDevice(blockDevice);
            VerifyGnuProperties(blockDevice);
        }

        protected void VerifyFifo(GnuTarEntry fifo)
        {
            VerifyPosixFifo(fifo);
            VerifyGnuProperties(fifo);
        }

        protected void VerifyGnuProperties(GnuTarEntry entry)
        {
            Assert.Equal(TestAccessTime, entry.AccessTime);
            Assert.Equal(TestChangeTime, entry.ChangeTime);
        }

        protected void VerifyGnuTimestamps(GnuTarEntry gnu)
        {
            Assert.Equal(default, gnu.AccessTime);
            Assert.Equal(default, gnu.ChangeTime);
        }
    }
}
