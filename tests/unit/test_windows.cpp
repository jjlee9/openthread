/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <SDKDDKVer.h>
#include "CppUnitTest.h"
#include "test_util.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#pragma region Test Declarations

// test_aes.cpp
void TestMacBeaconFrame();
void TestMacDataFrame();
void TestMacCommandFrame();

// test_hmac_sha256.cpp
void TestHmacSha256();

// test_link_quality.cpp
namespace Thread
{
    void TestRssAveraging();
    void TestLinkQualityCalculations();
}

// test_lowpan.cpp
namespace Thread
{
    void TestLowpanIphc();
}

// test_mac_frame.cpp
namespace Thread
{
    void TestMacHeader();
}

// test_message.cpp
void TestMessage();

// test_timer.cpp
int TestOneTimer();
int TestTenTimers();

// test_toolchain.cpp
void test_packed1();
void test_packed2();
void test_packed_union();

#pragma endregion

utAssertTrue s_AssertTrue;

namespace UnitTests
{		
	TEST_CLASS(UnitTest1)
	{
	public:

        UnitTest1() { s_AssertTrue = AssertTrue; }

        // Helper for openthread test code to call
        static void AssertTrue(bool condition, const wchar_t* message)
        {
            Assert::IsTrue(condition, message);
        }

        // test_aes.cpp
        TEST_METHOD(TestMacBeaconFrame) { ::TestMacBeaconFrame(); }
        TEST_METHOD(TestMacDataFrame) { ::TestMacDataFrame(); }
        TEST_METHOD(TestMacCommandFrame) { ::TestMacCommandFrame(); }

        // test_hmac_sha256.cpp
        TEST_METHOD(TestHmacSha256) { ::TestHmacSha256(); }

        // test_link_quality.cpp
        TEST_METHOD(TestRssAveraging) { Thread::TestRssAveraging(); }
        TEST_METHOD(TestLinkQualityCalculations) { Thread::TestLinkQualityCalculations(); }

        // test_lowpan.cpp
        TEST_METHOD(TestLowpanIphc) { Thread::TestLowpanIphc(); }

        // test_mac_frame.cpp
        TEST_METHOD(TestMacHeader) { Thread::TestMacHeader(); }

        // test_message.cpp
        TEST_METHOD(TestMessage) { ::TestMessage(); }

        // test_message.cpp
        TEST_METHOD(TestOneTimer) { ::TestOneTimer(); }
        TEST_METHOD(TestTenTimers) { ::TestTenTimers(); }

        // test_toolchain.cpp
        TEST_METHOD(test_packed1) { ::test_packed1(); }
        TEST_METHOD(test_packed2) { ::test_packed2(); }
        TEST_METHOD(test_packed_union) { ::test_packed_union(); }
	};
}