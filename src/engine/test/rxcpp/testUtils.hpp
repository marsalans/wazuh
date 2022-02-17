/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <mutex>

using namespace std;
using namespace rxcpp;

mutex m;

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

void printsafe(std::string s){
    m.lock();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] " << s << endl;
    m.unlock();
}



#endif // _TEST_UTILS_H